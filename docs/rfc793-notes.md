# RFC 793 Implementation Notes

Decisions and deviations from the spec made during implementation. Update per phase.

## Phase 1 — Header & Sequence Numbers

### Header codec (`pkg/tcp/header.go`)

- **RFC 793 §3.1 p.15 — Header layout**: 20-byte fixed header + 0–40 bytes options. DataOffset (4 bits) = header length / 4. Reserved bits (6 bits) spanning byte 12 low nibble + byte 13 bits 7–6. Control bits (6) low 6 bits of byte 13. All multi-byte fields network byte order (`encoding/binary.BigEndian`).
- **Reserved bits**: MVP enforces `reserved == 0` on Parse and returns `ErrReservedNotZero`. RFC 1122 §4.2.2.1 says receivers should ignore reserved bits, but strict check catches sender bugs early. Can be relaxed to tolerant (ignore) in phase 2 if interop requires. See header.go:Parse.
- **DataOffset validation**: Reject <5 or >15. Reject if header length > bytes available. Maximum header 60 bytes; maximum options 40 bytes.
- **Options & Padding**: Options carried opaquely as `[]byte` without padding on the API; `Marshal` pads with zero bytes to next 32-bit boundary and computes DataOffset. `Parse` strips trailing zero padding so `Header.Options` contains only meaningful bytes. This means a header sent as 24 bytes (`[0,0,0,0]` padding / EOL) round-trips to `Options == nil`/empty and re-marshals as 20 bytes. Canonically a 20-byte header with no options is preferred; wire-equivalence for all-zero options is intentional.
  - Future: add typed option parsing (EOL=0, NOP=1, MSS=2) with `ParseOptions`. Left extensible; MSS handled opaquely for now (RFC 793 §3.1, RFC 1122 §4.2.2.5).
- **Flags**: Constants `FlagFIN/SYN/RST/PSH/ACK/URG` as `1<<0..5` (`0x01..0x20`), mask `FlagMask=0x3F`. `Marshal` rejects flags with bits beyond the mask (`ErrInvalidFlagBits`). `HasFlag` helper for flag checks.
- **Checksum (RFC 793 §3.1 p.16, RFC 1071)**: One's complement sum over IPv4 pseudo-header (src 4 + dst 4 + zero + protocol 6 + TCP length 2) + TCP segment (header checksum zeroed + payload), odd tail padded with zero byte, carries folded. Computed on send via `MarshalWithChecksum`, verified on receive via `VerifyChecksum` (expects sum == 0xFFFF). Currently IPv4 only; IPv6 out of scope (returns error if non-v4 address). Checksum field is stored in network order at header bytes 16–17.
  - Verified against manual pseudo-header arithmetic and round-trip tests covering even/odd payload lengths. Golden segment test anchors determinism (Wireshark captures can be added as hex fixtures in a later iteration).
- **Parsing API**: `Parse(b)` returns `(*Header, payload, error)` without checksum verification — caller must invoke `VerifyChecksum(src,dst,segment)` where `segment` is the original byte slice (header+payload). This split allows tests over loopback without needing IP addresses for pure header tests.

### Sequence arithmetic (`internal/seq`)

- **RFC 793 §3.3 p.20 — Sequence space is 32-bit modulo 2³²**. Comparisons via `int32(a-b)` trick (Stevens Vol.2, Linux `after`/`before` macros). Provides `LT/GT/LTE/GTE/EQ`, `Add/Sub`, `Between` (half-open interval `[start,end)`). Used for `SND.UNA/NXT/WND` and `RCV.NXT/WND` window checks (RFC 793 §3.3 p.25). Coverage includes wrap-around edge cases (0xFFFFFFFF → 0).
- **Future**: `Between` will be used to test `RCV.NXT ≤ SEG.SEQ < RCV.NXT+RCV.WND`.

### Out of scope (phase 1)

- Congestion control, SACK / Window Scale / Timestamps (RFC 1323) — option bytes kept raw for forward compatibility as long as it can be done without breaking the code.
- IPv6 pseudo-header, URG semantics beyond carrying `UrgentPointer`.

## Phase 2 — State Machine & TCB

### State machine (`pkg/tcp/state.go`)

- **RFC 793 Figure 6 p.23**: 11 states `CLOSED → LISTEN → SYN-SENT → SYN-RECEIVED → ESTABLISHED → FIN-WAIT-1 → FIN-WAIT-2 → CLOSE-WAIT → CLOSING → LAST-ACK → TIME-WAIT → CLOSED`. Enum `StateClosed..StateTimeWait` with `String()` for debug. All transitions are table-driven for determinism (no sleeps, no I/O) per AGENTS.md Testing.
- **Two-level table**: `transitionTable` (state→set of reachable states) implements the diagram edges; `eventTable` (state×event→next state) encodes the skeleton event→transition needed for deterministic unit tests (AGENTS.md §6: `map[State]map[Event]Transition`). Illegal pairs return `ErrInvalidTransition` and leave state unchanged, matching RFC 793 §3.9 error handling (drop segment, remain in state).
- **Events**: `EventPassiveOpen/EventActiveOpen` (user OPEN), `SEND/RECEIVE/CLOSE/ABORT/STATUS`, segment arrivals `RCV_SYN/SYNACK/ACK/FIN/FINACK/RST`, and timeouts `RETRANSMIT, TIMEWAIT`. STATUS/SEND/RECEIVE are no-ops in synchronized states (`IsSynchronized()`) and illegal in CLOSED/LISTEN/SYN-*; phase 3 will add buffering semantics.
- **Helpers**: `CanTransitionTo`, `NextState(s,ev)`, `IsSynchronized`, `IsClosed`. `NextState` validates state existence (`ErrInvalidState`) and event legality. Reserved: simultaneous open `LISTEN→SYN-SENT` and simultaneous close `FIN-WAIT-1→CLOSING` are included per RFC 793 p.32.

### TCB (`pkg/tcp/tcb.go`)

- **RFC 793 §3.2 p.20**: Fields `ISS,SND.UNA/NXT/WND/UP/WL1/WL2, IRS,RCV.NXT/WND/UP`, 4-tuple, `State`, plus `SendBuf/RecvBuf` and `RetransmitQueue` placeholders (phase 4). Owned by a single goroutine (state machine loop); file header documents ownership (AGENTS.md Concurrency).
- **Initialization** (`NewTCB`, `NewListenTCB`): `SND.UNA←ISS`, `SND.NXT←ISS` (or `ISS+1` after SYN in `SYN-SENT/SYN-RECEIVED` where SYN consumes one seq per RFC 793 p.25), `SND.WND←0` (unknown), `SND.WL1←ISS`, `RCV.WND←rcvWnd` (0→`DefaultRcvWindow=65535`), `RCV.NXT←0` (→`IRS+1` after SYN). ISS is caller-supplied for deterministic tests; production will use clock-based ISN (RFC 793 p.27). `CloneForChild` duplicates a LISTEN TCB into `SYN-RECEIVED` with `IRS`/`RcvNxt=IRS+1` per passive open §3.8 p.34.
- **Window & ACK checks**: `InWindow(seq)` implements `RCV.NXT ≤ SEG.SEQ < RCV.NXT+RCV.WND` with wrapping (phase 4 will switch to `internal/seq.Between`); zero window only accepts `seq==RCV.NXT` (probe). `AckAcceptable(ack)` checks `SND.UNA ≤ ack ≤ SND.NXT` per §3.3 p.26; `UpdateSndUna`/`AdvanceRcvNxt/AdvanceSndNxt` mirror §3.9 ACK and SEQ updates. `SetState`/`HandleEvent` enforce the state diagram and auto-advance `RCV.NXT` on `RCV_SYN/SYNACK` when `IRS` is set.

### Out of scope (phase 2)

- Full segment acceptability (`SEQ+LEN` window checks for multi-byte segments, RST/FIN handling) — skeleton only (phase 3).
- Retransmission queue, RTO, 2MSL timer — `RetransmitQueue` placeholder (phase 4/5).
- Congestion control, ECN reserved bits relaxation — still strict `reserved==0` from phase 1.

## References

- RFC 793 https://datatracker.ietf.org/doc/html/rfc793
- RFC 1122 §4.2 https://datatracker.ietf.org/doc/html/rfc1122#page-84
- RFC 1071 Computing the Internet Checksum
