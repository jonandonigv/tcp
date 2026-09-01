# AGENTS.md — TCP RFC 793 Implementation in Go

This document guides human and AI agents working in this repository. The project scope has been reset to implement the Transmission Control Protocol as specified in RFC 793.

## 1. Project Overview

| Field | Value |
|-------|-------|
| **Goal** | Faithful implementation of TCP per RFC 793 (STD 7) in Go |
| **Module** | `github.com/jonandonigv/tcp` |
| **Go version** | 1.22.1 (see `go.mod:3`) |
| **Active branch** | `feat/rfc793` (branched from `master` @ `7e0da1a`) |
| **Reference spec** | https://datatracker.ietf.org/doc/html/rfc793 |
| **Related RFCs** | RFC 1122 (clarifications), RFC 2581 (congestion — out of scope initially) |

> **Reset note:** Code under `server/server.go:13` / `server/types.go:3` and `main.go:35` predates the RFC 793 reset and is considered legacy. Do not extend it — it will be replaced incrementally by RFC-compliant packages. Keep it building until explicitly removed.

## 2. Scope

### In Scope (MVP — RFC 793 Core)

1.  **TCP Header** `RFC 793 §3.1` — 20-byte fixed header + options (0–40 bytes):
    `SourcePort`, `DestPort`, `SeqNum` (32-bit), `AckNum` (32-bit), `DataOffset`, `Reserved`, `Flags` (URG/ACK/PSH/RST/SYN/FIN), `Window`, `Checksum`, `UrgentPointer`, `Options`, `Padding`. Encode/decode with correct network byte order and checksum (pseudo-header).
2.  **State Machine** `RFC 793 §3.2 / p.22` — `CLOSED → LISTEN → SYN-SENT → SYN-RECEIVED → ESTABLISHED → FIN-WAIT-1 → FIN-WAIT-2 → CLOSE-WAIT → CLOSING → LAST-ACK → TIME-WAIT → CLOSED`. Event-driven via segments, user calls (`OPEN`, `SEND`, `RECEIVE`, `CLOSE`, `ABORT`, `STATUS`) and timeouts.
3.  **Transmission Control Block (TCB)** `RFC 793 §3.2` — per-connection state: send/receive sequence variables (`SND.UNA/NXT/WND/UP/WL1/WL2`, `RCV.NXT/WND/UP`), buffers, retransmission queue.
4.  **Connection Lifecycle:**
    *   Three-way handshake `RFC 793 §3.4` (active/passive open).
    *   Data transfer — segmentation, sequencing, acknowledgment, windowing.
    *   Graceful close (FIN) and abort (RST).
5.  **Sequence Numbers & Reliability** — 32-bit wrapping arithmetic, duplicate detection, in-order delivery, retransmission (RTO) with exponential backoff.
6.  **Flow Control** — sliding window, window updates, zero-window probing.
7.  **IP-layer integration** — raw IP or TUN/TAP abstraction so tests run without privileged sockets; pluggable `NetworkAdapter` interface.

### Out of Scope (Until MVP Passes)

* Congestion control (RFC 2581: slow start, congestion avoidance).
* SACK / Window Scaling / Timestamps (RFC 1323) — leave option parsing extensible.
* TLS, application protocols.
* IPv6 (initially IPv4 only).

### Non-Goals

* Production-grade performance tuning.
* Kernel-bypass / DPDK.
* Full RFC 1122 strictness on day one — correctness first, edge-case hardening second.

## 3. Repository Structure

Target layout (create incrementally — do not create empty stubs without an issue):

```
.
├── AGENTS.md
├── go.mod
├── main.go                 # legacy demo — to be replaced by cmd/ example
├── cmd/
│   └── example/            # tiny CLI to exercise the stack
├── pkg/
│   ├── tcp/                # core protocol
│   │   ├── header.go       # marshaling, checksum
│   │   ├── header_test.go
│   │   ├── tcb.go          # Transmission Control Block
│   │   ├── state.go        # state enum + transitions
│   │   ├── control.go      # open/close/abort logic
│   │   └── stack.go        # orchestration / demux
│   ├── retransmit/         # RTO, timers
│   └── netadapter/         # TUN/TAP or raw socket adapter interface
├── internal/
│   └── seq/                # 32-bit seq helpers (LT/GT with wrapping)
└── docs/
    └── rfc793-notes.md     # implementation decisions vs spec
```

Current legacy paths `server/` will be deprecated once `pkg/tcp` is functional. Prefer `pkg/` for new code.

## 4. Agent Workflow

### Before Writing Code

1. Read this file and `go.mod`.
2. Check `git status` / `git branch --show-current` — all work stays on `feat/rfc793` or `feat/rfc793/*` sub-branches.
3. Search for existing types before duplicating (e.g., `grep TCPHeader`).

### Branch & Commit

* Branch from `feat/rfc793`: `feat/rfc793/<short-topic>` (e.g., `feat/rfc793/header-codec`).
* Conventional Commits: `feat(tcp): implement header checksum`, `fix(tcb): handle SYN in LISTEN`, `test(header): add pseudo-header cases`.
* Keep commits small and passing `go vet` / `go test ./...`.

### Coding Rules

1. **No new dependencies without discussion.** Stdlib-first (`encoding/binary`, `net`, `net/netip`).
2. **Unexported by default.** Export only what `cmd/` or tests need.
3. **Errors:** wrap with `fmt.Errorf("tcp: ...: %w", err)`, sentinel errors for spec violations (`ErrChecksumMismatch`, `ErrInvalidState`).
4. **Concurrency:** TCB is owned by one goroutine; synchronize via channels. No shared mutable state without `sync.Mutex` and a comment justifying it. Document goroutine ownership in file header.
5. **Formatting:** `gofmt` + `go vet` clean. CI will enforce. Run `golangci-lint` if available.
6. **Comments:** Reference RFC section when implementing spec logic, e.g. `// RFC 793 §3.3 p.25 — segment arrives in SYN-RECEIVED`.
7. **No TODOs without issue link:** `// TODO(#12): handle simultaneous open`.

### Testing

* Table-driven tests, `*_test.go` alongside code.
* Unit: header codec, seq arithmetic, state transitions (determinism — no sleeps).
* Integration: handshake + data transfer over `net.Pipe` or mock `netadapter` (no root required). Use `loopback` / TUN in CI if available.
* Run: `go test ./... -count=1 -race` must pass before push.
* Golden segments: capture known-good Wireshark TCP hex dumps for checksum/length regression.

### Verification Checklist (for every PR)

- [ ] `go test ./... -race` green
- [ ] `go vet ./...` green
- [ ] RFC section cited in code comment for non-trivial logic
- [ ] No privileged socket required for tests
- [ ] `docs/rfc793-notes.md` updated if deviating from spec

## 5. Implementation Roadmap

| Phase | Deliverable | Key Files |
|-------|-------------|-----------|
| **0** | Branch + AGENTS.md + `docs/rfc793-notes.md` | this file |
| **1** | `internal/seq` + `pkg/tcp/header.go` (codec, checksum, options) | `header.go`, `seq/` |
| **2** | `pkg/tcp/state.go` + `tcb.go` (state machine skeleton, TCB init) | `state.go`, `tcb.go` |
| **3** | Handshake (passive + active open) — LISTEN ↔ ESTABLISHED | `control.go` |
| **4** | Data path: send/receive, ack, window, retransmit queue | `stack.go`, `retransmit/` |
| **5** | Close/Abort: FIN/RST, TIME-WAIT timer (2MSL) | `control.go` |
| **6** | Integration example + loopback tests, deprecate `server/` | `cmd/example/`, `main.go` |

Do not skip phases. Each phase merges to `feat/rfc793` via PR after review.

## 6. Key RFC 793 Concepts for Agents

* **Segment format:** `Header [20..60] + Data`. Header length = `DataOffset * 4`.
* **Sequence space:** 32-bit unsigned, arithmetic modulo 2³². Use helper `seq.LT(a,b) bool`.
* **Flags vs Control Bits:** `URG|ACK|PSH|RST|SYN|FIN` — `ACK` may be combined with any.
* **Window:** advertises `RCV.WND` bytes willing to accept starting at `RCV.NXT`.
* **Checksum:** one's complement over pseudo-header (src/dst IP, protocol=6, TCP length) + TCP segment with checksum field zeroed. Must be computed on send, verified on receive.
* **State diagram:** see RFC 793 Figure 6 (p.23). Implement as `map[State]map[Event]Transition`.

## 7. Interfaces to Respect

```go
// pkg/netadapter — injectable L3
type Adapter interface {
    Read() ([]byte, error)   // raw IP packet or TCP segment depending on mode
    Write([]byte) error
    Close() error
    LocalAddr() netip.Addr
}

// pkg/tcp — user-facing (BSD socket style)
type Stack interface {
    Listen(port uint16) (Listener, error)
    Dial(ip netip.Addr, port uint16) (Conn, error)
}
```

Keep interfaces narrow; add methods only with tests.

## 8. Do / Do Not

**Do:**
* Read the RFC before coding a feature — link the page number.
* Prefer small, reviewable PRs (≤300 LOC).
* Update this file if a rule proves wrong — via PR.

**Do Not:**
* Copy kernel TCP code verbatim — understand and re-express.
* Introduce `net.Listen("tcp", ...)` as the *implementation* of TCP — that bypasses RFC 793. `net` is for the adapter/tests only.
* Commit generated binaries, pcap dumps, or secrets.
* Force-push to `feat/rfc793` or `master`.

## 9. References

* RFC 793 — https://datatracker.ietf.org/doc/html/rfc793
* RFC 793 Errata & RFC 1122 §4.2 — https://datatracker.ietf.org/doc/html/rfc1122#page-84
* Stevens, *TCP/IP Illustrated Vol.2* — state machine.
* `go.mod:1` — module path.

## 10. Getting Started (for a new agent session)

```bash
git status
git branch --show-current   # expect feat/rfc793
go vet ./...
go test ./... -count=1 -race
# pick next phase from §5, create feat/rfc793/<topic>, implement, test, PR
```

Questions or spec ambiguities → open a draft PR with `RFC 793 §X.Y — question:` in title so discussion is tracked.
