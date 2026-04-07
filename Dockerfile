# hanzoai/sqlite — distributed encrypted SQLite
# CGO required for go-sqlite3 + sqlcipher
FROM golang:1.26-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlcipher-dev gcc libc6-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=1 go build -tags "sqlite_fts5 sqlcipher" -o /usr/local/bin/sqlite-test ./...
RUN CGO_ENABLED=1 go test -tags "sqlite_fts5 sqlcipher" -count=1 ./...

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlcipher0 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Library only — no binary to ship. Used as a base image.
