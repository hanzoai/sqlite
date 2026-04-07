# Hanzo SQLite

Distributed SQLite with sqlcipher encryption, CRDT replication, and Raft consensus.

Drop-in replacement for `modernc.org/sqlite` in Hanzo Base with:
- **Encryption at rest**: sqlcipher (AES-256-CBC page-level encryption)
- **Distributed replication**: Raft consensus for multi-node (LiteFS-style)
- **CRDT sync**: conflict-free replicated data types for eventual consistency
- **Multi-party sharding**: each party runs a node, threshold for writes

## Architecture

```
┌─────────────────────────────────────────────┐
│              Hanzo SQLite Node               │
├─────────────────────────────────────────────┤
│  Application (Hanzo Base)                    │
│    ↕ database/sql driver                    │
│  SQLCipher Engine (AES-256-CBC pages)       │
│    ↕ WAL intercept                          │
│  Replication Layer                           │
│    ├─ Raft (strong consistency, writes)     │
│    └─ CRDT (eventual consistency, reads)    │
│    ↕ ZAP transport                          │
│  Peer Discovery (mDNS or explicit)          │
└─────────────────────────────────────────────┘
```

## Modes

| Mode | Consistency | Use Case |
|------|-------------|----------|
| `single` | Local only | Development, single-instance prod |
| `raft` | Strong (leader writes) | Multi-node KMS, MPC state |
| `crdt` | Eventual (all write) | Edge sync, offline-first apps |
| `threshold` | t-of-n attest writes | MPC wallet shards, multi-party |

## Multi-Party Threshold Mode

Multiple parties each run a node. Write operations require t-of-n attestations:

```
Party A (node-0) ──┐
Party B (node-1) ──┼── 2-of-3 attest ──→ write committed
Party C (node-2) ──┘
```

Each party signs their attestation locally. Simple 2/3 threshold for writes.
Reads are local (each node has a full replica).

## Encryption

SQLCipher provides transparent page-level encryption:
- Algorithm: AES-256-CBC
- KDF: PBKDF2-HMAC-SHA512 (256K iterations)
- HMAC: SHA-512 per-page integrity
- Key: derived from passphrase or provided as raw 256-bit key

```go
db, err := sqlite.Open("data.db", sqlite.WithKey("my-passphrase"))
// or
db, err := sqlite.Open("data.db", sqlite.WithRawKey(keyBytes))
```

## Usage

```go
import "github.com/hanzoai/sqlite"

// Single node (encrypted)
db, err := sqlite.Open("data.db", sqlite.WithKey("passphrase"))

// Raft cluster (3 nodes, encrypted)
db, err := sqlite.Open("data.db",
    sqlite.WithKey("passphrase"),
    sqlite.WithRaft("node-0", ":4001", []string{
        "node-1:4001",
        "node-2:4001",
    }),
)

// Threshold mode (2-of-3 for writes)
db, err := sqlite.Open("data.db",
    sqlite.WithKey("passphrase"),
    sqlite.WithThreshold(2, 3, mySigningKey),
    sqlite.WithPeers([]string{
        "node-1:4001",
        "node-2:4001",
    }),
)
```

## Integration with Hanzo Base

Replace `modernc.org/sqlite` in Base's `go.mod`:

```
replace modernc.org/sqlite => github.com/hanzoai/sqlite v0.1.0
```

Base gets encryption at rest + distribution for free. No code changes needed.

## License

Apache-2.0
