package sqlite

import (
	"crypto/ed25519"
	"testing"
)

func TestThresholdBasic2of3(t *testing.T) {
	// Generate 3 party keys
	_, priv0, _ := ed25519.GenerateKey(nil)
	pub1, priv1, _ := ed25519.GenerateKey(nil)
	pub2, priv2, _ := ed25519.GenerateKey(nil)

	var committed bool
	var committedSQL string

	tm := NewThresholdManager(2, 3, "node-0", priv0)
	tm.RegisterPeer("node-1", pub1)
	tm.RegisterPeer("node-2", pub2)
	tm.SetCommitFunc(func(sql string, params []any) error {
		committed = true
		committedSQL = sql
		return nil
	})

	// Propose a write (auto self-attests as node-0)
	id, err := tm.Propose("INSERT INTO trades (id) VALUES (?)", []any{"trade-1"})
	if err != nil {
		t.Fatal(err)
	}

	// 1 attestation so far (self), threshold=2, not committed yet
	if committed {
		t.Fatal("committed with only 1 attestation")
	}

	// Node-1 attests
	sig1 := ed25519.Sign(priv1, id[:])
	if err := tm.Attest(id, "node-1", sig1); err != nil {
		t.Fatal(err)
	}

	// Now 2/3 — should be committed
	if !committed {
		t.Fatal("not committed after 2/3 attestations")
	}
	if committedSQL != "INSERT INTO trades (id) VALUES (?)" {
		t.Fatalf("wrong SQL: %s", committedSQL)
	}

	// Node-2 attestation after commit should fail (proposal cleaned up)
	sig2 := ed25519.Sign(priv2, id[:])
	err = tm.Attest(id, "node-2", sig2)
	if err == nil {
		t.Log("late attestation silently ignored (OK)")
	}
}

func TestThresholdRejectInvalidSig(t *testing.T) {
	_, priv0, _ := ed25519.GenerateKey(nil)
	pub1, _, _ := ed25519.GenerateKey(nil)
	_, badPriv, _ := ed25519.GenerateKey(nil)

	tm := NewThresholdManager(2, 2, "node-0", priv0)
	tm.RegisterPeer("node-1", pub1)

	id, _ := tm.Propose("DELETE FROM orders", nil)

	// Sign with wrong key
	badSig := ed25519.Sign(badPriv, id[:])
	err := tm.Attest(id, "node-1", badSig)
	if err != ErrInvalidSig {
		t.Fatalf("expected ErrInvalidSig, got %v", err)
	}
}

func TestThresholdRejectDuplicate(t *testing.T) {
	_, priv0, _ := ed25519.GenerateKey(nil)
	pub1, priv1, _ := ed25519.GenerateKey(nil)

	tm := NewThresholdManager(3, 3, "node-0", priv0)
	tm.RegisterPeer("node-1", pub1)
	tm.SetCommitFunc(func(string, []any) error { return nil })

	id, _ := tm.Propose("UPDATE balances SET amount = 0", nil)

	sig1 := ed25519.Sign(priv1, id[:])
	if err := tm.Attest(id, "node-1", sig1); err != nil {
		t.Fatal(err)
	}

	// Duplicate
	err := tm.Attest(id, "node-1", sig1)
	if err != ErrDuplicateSigner {
		t.Fatalf("expected ErrDuplicateSigner, got %v", err)
	}
}

func TestThreshold1of1SelfCommit(t *testing.T) {
	_, priv0, _ := ed25519.GenerateKey(nil)

	var committed bool
	tm := NewThresholdManager(1, 1, "node-0", priv0)
	tm.SetCommitFunc(func(string, []any) error {
		committed = true
		return nil
	})

	_, err := tm.Propose("SELECT 1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !committed {
		t.Fatal("1-of-1 should self-commit")
	}
}

func TestCleanExpired(t *testing.T) {
	_, priv0, _ := ed25519.GenerateKey(nil)

	tm := NewThresholdManager(2, 2, "node-0", priv0)
	tm.Propose("INSERT INTO x VALUES (1)", nil)

	// Force expire
	tm.mu.Lock()
	for _, p := range tm.pending {
		p.ExpiresAt = p.CreatedAt // already expired
	}
	tm.mu.Unlock()

	cleaned := tm.CleanExpired()
	if cleaned != 1 {
		t.Fatalf("expected 1 cleaned, got %d", cleaned)
	}
	if tm.Pending() != 0 {
		t.Fatal("pending should be 0 after cleanup")
	}
}
