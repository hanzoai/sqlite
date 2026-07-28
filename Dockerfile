# hanzoai/sqlite — distributed encrypted SQLite
# CGO required for go-sqlite3 + sqlcipher
FROM golang:1.26.5-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlcipher-dev gcc libc6-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Build + test with the CODEC ACTUALLY LINKED. The `-tags "sqlite_fts5 sqlcipher"`
# recipe is INERT: mattn/go-sqlite3 has no `sqlcipher` tag, so it links plain
# sqlite and silently ships PLAINTEXT — CodecLinked()=false and TestEncryptionProof
# SKIPS, so the "gate" proves nothing. The working recipe is `-tags libsqlite3`
# plus the codec CFLAGS/LDFLAGS (matches object/orgdb.go's CLAUDE.md and IAM's prod
# image). Debian's libsqlcipher-dev installs headers under /usr/include/sqlcipher.
ENV CGO_ENABLED=1 \
    CGO_CFLAGS="-DSQLITE_HAS_CODEC -DSQLITE_USE_URI=1 -I/usr/include/sqlcipher" \
    CGO_LDFLAGS="-lsqlcipher"

RUN go build -tags "libsqlite3 sqlite_fts5" -o /usr/local/bin/sqlite-test ./...
# The proof test MUST run (not skip) here: a linked codec yields CodecLinked()=true
# and asserts real ciphertext on disk. SQLITE_REQUIRE_CODEC=1 turns the test's
# "codec unlinked" skip into a HARD FAILURE, so a regression to the inert-tag
# recipe fails the build instead of shipping plaintext.
RUN SQLITE_REQUIRE_CODEC=1 go test -tags "libsqlite3 sqlite_fts5" -count=1 ./...

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlcipher0 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Library only — no binary to ship. Used as a base image.
