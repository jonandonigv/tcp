# tcp — RFC 793 Implementation in Go

Faithful implementation of the Transmission Control Protocol (TCP) as specified in [RFC 793 (STD 7)](https://datatracker.ietf.org/doc/html/rfc793) in Go. Started from a scope reset on `feat/rfc793` — the legacy `server/` package is retained only for build compatibility and will be replaced incrementally.

> Spec-first, stdlib-first, no privileged sockets required for tests.

## Project Status

**Phase 0 – 5 — Complete** (branch + `AGENTS.md`, phases 1–5 on `feat/rfc793`)

| Phase | Deliverable | Status |
|-------|-------------|--------|
| 0 | Branch `feat/rfc793` + `AGENTS.md` + `docs/rfc793-notes.md` | ✅ Done |
| 1 | `internal/seq` + `pkg/tcp/header.go` (codec, checksum, options) | ✅ Done |
| 2 | `pkg/tcp/state.go` + `tcb.go` (state machine, TCB) | ✅ Done |
| 3 | Handshake (LISTEN ↔ ESTABLISHED) | ✅ Done |
| 4 | Data path (send/receive, ack, window, retransmit) | ✅ Done |
| 5 | Close/Abort (FIN/RST, TIME-WAIT 2MSL) | ✅ Done |
| 6 | Integration example + loopback tests, deprecate `server/` | 🚧 Phase 6a deprecation committed, 6b example+tests next |

> **Deprecation (Phase 6a):** `server/` (`server/server.go:13`, `server/types.go:3`) and `main.go:35` are deprecated (RFC 793 reset, AGENTS.md §1). Retained solely for `go vet`/`go test` build compatibility. New code must use `pkg/tcp` and `cmd/example`; removal tracked post-6b.

See `AGENTS.md:5` for the full roadmap and `docs/rfc793-notes.md` for spec deviations.

## Repository Structure

```
.
├── AGENTS.md               # agent workflow, coding rules, roadmap
├── README.md
├── LICENSE                 # MIT
├── go.mod                  # module github.com/jonandonigv/tcp, go 1.22.1
├── main.go                 # legacy demo (to be replaced by cmd/example)
├── server/                 # legacy — deprecated after pkg/tcp is functional
├── pkg/
│   ├── tcp/                # core protocol (header, state, TCB, stack)
│   ├── retransmit/         # RTO, timers
│   └── netadapter/         # TUN/TAP or raw socket adapter interface
├── internal/seq/           # 32-bit sequence arithmetic (wrapping)
├── cmd/example/            # CLI to exercise the stack
└── docs/rfc793-notes.md    # implementation decisions vs spec
```

All `pkg/tcp`, `pkg/retransmit`, `internal/seq` paths exist since phases 1–5; `cmd/example` lands in 6b. `server/` remains deprecated but building (Phase 6a).

## Getting Started

```bash
git clone https://github.com/jonandonigv/tcp.git
cd tcp
git checkout feat/rfc793
go vet ./...
go test ./... -count=1 -race
```

Pick the next phase from `AGENTS.md:5`, create a topic branch `feat/rfc793/<short-topic>`, implement with RFC section citations, and open a PR against `feat/rfc793`.

### Agent Quickstart

```bash
git status
git branch --show-current   # expect feat/rfc793
go vet ./...
go test ./... -count=1 -race
```

Read `AGENTS.md:4` before writing code (branch naming, conventional commits, concurrency rules, testing).

## Development Rules (Summary)

* **Stdlib-first** — no new dependencies without discussion (`encoding/binary`, `net/netip`).
* **Unexported by default**, RFC section cited in comments (`// RFC 793 §3.1`).
* **TCB owned by one goroutine** — synchronize via channels.
* **Tests:** table-driven, deterministic, no `sleep`, no privileged sockets. Golden segments from Wireshark for checksums.
* **Commits:** Conventional Commits, small PRs ≤300 LOC, `go vet` + `go test -race` green.

Full rules in `AGENTS.md:4`.

## References

* RFC 793 — https://datatracker.ietf.org/doc/html/rfc793
* RFC 1122 §4.2 — https://datatracker.ietf.org/doc/html/rfc1122#page-84
* Stevens, *TCP/IP Illustrated Vol. 2* — state machine
* `go.mod:1` — module path

## License

MIT — see [LICENSE](LICENSE).
