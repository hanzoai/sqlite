// Threshold write attestation for multi-party SQLite.
//
// Each party runs a node with a full replica. Write operations require
// t-of-n parties to sign the write before it's committed. Reads are local.
//
// Use case: MPC wallet shard storage, DEX trade approvals, multi-sig
// transaction authorization in liquidity/ats.
package sqlite

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrThresholdNotMet = errors.New("sqlite: threshold attestations not met")
	ErrDuplicateSigner = errors.New("sqlite: duplicate signer")
	ErrInvalidSig      = errors.New("sqlite: invalid attestation signature")
	ErrSessionExpired  = errors.New("sqlite: attestation session expired")
)

// WriteProposal is a proposed write that needs t-of-n attestations.
type WriteProposal struct {
	ID        [32]byte  // SHA-256 of the SQL + params
	SQL       string
	Params    []any
	Proposer  string    // node ID of proposer
	CreatedAt time.Time
	ExpiresAt time.Time

	mu           sync.Mutex
	attestations map[string][]byte // nodeID → Ed25519 signature
}

// ThresholdManager coordinates multi-party write attestation.
type ThresholdManager struct {
	threshold  int
	parties    int
	nodeID     string
	signingKey ed25519.PrivateKey
	peerKeys   map[string]ed25519.PublicKey // nodeID → public key

	mu       sync.Mutex
	pending  map[[32]byte]*WriteProposal
	commitFn func(sql string, params []any) error
}

// NewThresholdManager creates a threshold write coordinator.
func NewThresholdManager(threshold, parties int, nodeID string, signingKey ed25519.PrivateKey) *ThresholdManager {
	return &ThresholdManager{
		threshold:  threshold,
		parties:    parties,
		nodeID:     nodeID,
		signingKey: signingKey,
		peerKeys:   make(map[string]ed25519.PublicKey),
		pending:    make(map[[32]byte]*WriteProposal),
	}
}

// RegisterPeer adds a peer's public key for attestation verification.
func (tm *ThresholdManager) RegisterPeer(nodeID string, pubKey ed25519.PublicKey) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.peerKeys[nodeID] = pubKey
}

// SetCommitFunc sets the function called when threshold is met.
func (tm *ThresholdManager) SetCommitFunc(fn func(string, []any) error) {
	tm.commitFn = fn
}

// Propose creates a new write proposal. Returns the proposal ID.
func (tm *ThresholdManager) Propose(sql string, params []any) ([32]byte, error) {
	id := hashProposal(sql, params)

	proposal := &WriteProposal{
		ID:           id,
		SQL:          sql,
		Params:       params,
		Proposer:     tm.nodeID,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(30 * time.Second),
		attestations: make(map[string][]byte),
	}

	// Self-attest
	sig := ed25519.Sign(tm.signingKey, id[:])
	proposal.attestations[tm.nodeID] = sig

	tm.mu.Lock()
	tm.pending[id] = proposal
	tm.mu.Unlock()

	// Check if self-attestation meets threshold (1-of-1)
	if len(proposal.attestations) >= tm.threshold {
		return id, tm.tryCommit(id)
	}

	return id, nil
}

// Attest adds a peer's attestation to a pending proposal.
func (tm *ThresholdManager) Attest(proposalID [32]byte, nodeID string, signature []byte) error {
	tm.mu.Lock()
	proposal, ok := tm.pending[proposalID]
	tm.mu.Unlock()

	if !ok {
		return fmt.Errorf("sqlite: proposal %x not found", proposalID[:8])
	}

	if time.Now().After(proposal.ExpiresAt) {
		return ErrSessionExpired
	}

	// Verify signature
	pubKey, ok := tm.peerKeys[nodeID]
	if !ok {
		return fmt.Errorf("sqlite: unknown peer %s", nodeID)
	}
	if !ed25519.Verify(pubKey, proposalID[:], signature) {
		return ErrInvalidSig
	}

	proposal.mu.Lock()
	if _, dup := proposal.attestations[nodeID]; dup {
		proposal.mu.Unlock()
		return ErrDuplicateSigner
	}
	proposal.attestations[nodeID] = signature
	count := len(proposal.attestations)
	proposal.mu.Unlock()

	// Check threshold
	if count >= tm.threshold {
		return tm.tryCommit(proposalID)
	}

	return nil
}

// tryCommit executes the write if threshold is met.
func (tm *ThresholdManager) tryCommit(id [32]byte) error {
	tm.mu.Lock()
	proposal, ok := tm.pending[id]
	if ok {
		delete(tm.pending, id)
	}
	tm.mu.Unlock()

	if !ok || tm.commitFn == nil {
		return nil
	}

	return tm.commitFn(proposal.SQL, proposal.Params)
}

// Pending returns the number of pending proposals.
func (tm *ThresholdManager) Pending() int {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return len(tm.pending)
}

// CleanExpired removes expired proposals.
func (tm *ThresholdManager) CleanExpired() int {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	now := time.Now()
	cleaned := 0
	for id, p := range tm.pending {
		if now.After(p.ExpiresAt) {
			delete(tm.pending, id)
			cleaned++
		}
	}
	return cleaned
}

func hashProposal(sql string, params []any) [32]byte {
	h := sha256.New()
	h.Write([]byte(sql))
	for _, p := range params {
		b := []byte(fmt.Sprintf("%v", p))
		binary.Write(h, binary.LittleEndian, uint32(len(b)))
		h.Write(b)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
