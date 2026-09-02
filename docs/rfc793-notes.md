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

## Phase 3 — Handshake (LISTEN ↔ ESTABLISHED)

### Control (`pkg/tcp/control.go`)

- **RFC 793 §3.4 p.33 / §3.8 p.33 active/passive OPEN**: `ActiveOpen(local,remote,iss,rcvWnd)` creates `SYN-SENT` (`SND.UNA←ISS`, `SND.NXT←ISS+1` per `NewTCB`) and returns initial `SYN` (`Seq=ISS`, `Window=RcvWnd`). `PassiveOpen`/`NewListenTCB` creates `LISTEN` (`SND.NXT==ISS==0`, no SYN yet). `HandleListenSegment(listen, seg, iss)` implements LISTEN acceptability p.65-66: ignore `RST`, ignore `ACK`, drop non-`SYN`, clone child via `CloneForChild(iss, irs=SEG.SEQ)` → `SYN-RECEIVED` (`RCV.NXT←IRS+1`, `SND.WND←SEG.WND`) and return `SYN-ACK` (`SYN|ACK Seq=ISS Ack=IRS+1`). `HandleListenSegmentWithAddrs` variant carries peer IP for demux; both preserve table-driven determinism — no I/O, no sleeps.
- **SYN-SENT** (RFC 793 p.36 / §3.9 p.66-67): `HandleSegment` dispatches per flag combo. `RST` acceptable only if `AckAcceptable` (ACK acks our SYN) → `CLOSED` + `ErrConnectionReset`; `SYN+ACK` validates `AckAcceptable`, updates `IRS/RCV.NXT←IRS+1`, `SND.WND/WL1/WL2`, `UpdateSndUna`, transitions `SYN-SENT→ESTABLISHED` (p.36 step 5) and returns `ACK` (`Seq=SND.NXT==ISS+1`, `Ack=RCV.NXT`). `SYN` alone (simultaneous open p.32) → `SYN-RECEIVED` with retransmit `SYN-ACK` (`Seq=ISS`). Lone `ACK` without `SYN` dropped. `ACK` not in `[SND.UNA,SND.NXT]` → `ErrAckNotAcceptable`.
- **SYN-RECEIVED** (RFC 793 p.36 / p.68): `RST` → `CLOSED`; `ACK` must be `AckAcceptable` else `ErrAckNotAcceptable`; duplicate `SYN` retransmits `SYN-ACK`; valid `ACK` (`Ack==SND.NXT`) updates `SND.UNA/WND/WL1/WL2` and `SYN-RECEIVED→ESTABLISHED` with no reply (p.36). No data path — phase 4 handles SEQ+LEN window checks, FIN/RST in synchronized states (`ESTABLISHED→CLOSED` on `RST` per p.68, `ACK` window validation per p.69).
- **Helpers**: `BuildAck(tcb)` (`Seq=SND.NXT Ack=RCV.NXT`), `ErrSegmentUnexpected/ErrConnectionReset/ErrAckNotAcceptable`. All logic references RFC page; tests exercise handshake without raw sockets via `Header` structs only (no privileged I/O).

### Out of scope (phase 3)

- Data transfer, segmentation, retransmission/RTO, zero-window probing (phase 4).
- Graceful close `FIN`/`TIME-WAIT 2MSL` and abort `RST` generation for `CLOSED` (phase 5).
- MSS/Options negotiation — header options remain opaque as in phase 1.

## Phase 4 — Data Path (send/receive, ack, window, retransmit)

### Data path (`pkg/tcp/data.go`)

- **RFC 793 §3.3 p.25-26 segment acceptability / §3.9 p.69-70**: `IsSegmentAcceptable(tcb,hdr,payloadLen)` checks `SEG.SEQ`/`SEG.LEN` (SYN/FIN count as 1, RFC 793 p.25) against `[RCV.NXT, RCV.NXT+RCV.WND)` and overlap into window; zero-length `SEQ==RCV.NXT` case and zero-window probe handled. Uses wrapping arithmetic (`int32`) equivalent to `internal/seq.Between`.
- **Send** (`Send(tcb,q,data,mss)`) per §3.7 p.42: synchronized states only (`ESTABLISHED/CLOSE-WAIT` etc.), `MSS` chunking (`DefaultMSS=1460`, RFC 793 §3.7 536-byte default noted), `SND.WND` flow control (`usable = SND.WND - (SND.NXT-SND.UNA)`, zero-window → `ErrZeroWindow`), builds `PSH|ACK` headers (`Seq=SND.NXT`, `Ack=RCV.NXT`, `Window=RcvWnd`), advances `SND.NXT`, enqueues each segment into `retransmit.Queue` (copied payload, `SentAt` captured). Respects window; excess data truncated to usable window.
- **Receive** (`Recv(tcb,q,hdr,payload)`) per §3.9 p.69-70: validates `RST→CLOSED` per p.68, acceptability (unacceptable → duplicate `ACK <SEQ=SND.NXT><ACK=RCV.NXT>` per p.69), `ACK` processing (`AckAcceptable`, `UpdateSndUna`, `q.Ack`, window update via `SND.WL1/WL2` check `SEQ>WL1` or `SEQ==WL1 && ACK>=WL2` per p.70), in-order delivery (`SEQ==RCV.NXT` → advance `RCV.NXT`, deliver, drain `Reassembly` map for contiguous buffered segments), duplicate (`SEQ<RCV.NXT` → duplicate ACK), out-of-order buffering (map `Reassembly[SEQ]→payload` within window, next ACK), `FIN` consumes 1 sequence beyond payload and stays `ESTABLISHED` (close moves to phase 5). Pure ACK with no data returns no deliver/ack.
- **Retransmission queue** (`pkg/retransmit/queue.go`): goroutine-local `Queue{entries[]Entry{Seq,Payload,SentAt,Attempts}}`, `Enqueue` copies payload, `Ack(ack)` removes entries where `ack >= Seq+Len` wrapping-aware (RFC 793 p.41 `SND.UNA` advance), `NeedsRetransmit(rto)` and `Retransmit()` for RTO expiry. Deterministic via injected `nowFn` (no sleeps).
- **RTO** (`pkg/retransmit/rto.go`): RFC 6298 §2 SRTT/RTTVAR/RTO (`alpha=1/8 beta=1/4`, `RTO=SRTT+max(G,4*RTTVAR)`, clamp `[200ms,60s]`), `Update(rtt)`, `Backoff()` exponential `*2` per RFC 793 p.42, `Timeout()`; deterministic initial `1s`.

### Stack demux (`pkg/tcp/stack.go`)

- **RFC 793 §3.9 demux / AGENTS.md §7 `NetworkAdapter`**: minimal `Stack{tcbs map[4-tuple]→TCB}` for loopback tests (no privileged sockets), `Add/Lookup` (exact 4-tuple fallback to `LISTEN` on same local), `Deliver(local,remote,hdr,payload,iss,q)` dispatches to `HandleListenSegmentWithAddrs` or `HandleSegment`/`Recv` per state and updates retransmit queue. Placeholder for `netadapter` TUN/TAP integration in phase 6.

### Out of scope (phase 4)

- Congestion control (slow start / congestion avoidance, RFC 2581) — window is flow control only.
- Delayed ACK, Nagle, urgent pointer processing — `PSH` set on all data segments, `URG` still carried opaquely.
- SACK / Window Scaling / Timestamps (RFC 1323) — option parsing extensible as in phase 1.

## Phase 5 — Close/Abort (FIN/RST, TIME-WAIT 2MSL)

### Control close (`pkg/tcp/control.go` phase 5)

- **RFC 793 §3.8 p.33 CLOSE / §3.9 p.71 graceful close**: `Close(tcb,q)` enforces Figure 6 user `CLOSE`: `ESTABLISHED→FIN-WAIT-1`, `CLOSE-WAIT→LAST-ACK`, `SYN-RECEIVED→FIN-WAIT-1` else `ErrInvalidClose`; builds `FIN|ACK Seq=SND.NXT Ack=RCV.NXT Window=RcvWnd`, enqueues 1-byte dummy into `retransmit.Queue` (FIN consumes 1 per p.25 `Ack(Seq+1)` clears), advances `SND.NXT` by 1, transitions via `CanTransitionTo`. `Default2MSL=60s` (RFC 793 p.42 MSL=120s; 60s is common `2MSL` trim for tests).
- **Abort** (`Abort(tcb,q)` per §3.8 p.34 ABORT): clears `q`, moves `*→CLOSED` (including `TIME-WAIT`), wipes `TimeWaitUntil`, returns `RST Seq=SND.NXT`. RST handling already in `HandleSegment`/`Recv` per p.68: `SYN-SENT` RST acceptable only if `AckAcceptable`, synchronized `RST→CLOSED`, `LISTEN` RST ignored, `CLOSED` send RST. New `ErrInvalidClose` for illegal CLOSE.
- **FIN arrival** (`handleFin`/`handleFinAck` per §3.9 p.70-71): control path validates `AckAcceptable` (RFC 793 p.69) and `ACK` advances `SND.UNA`, then `FIN` consumes 1 (`RCV.NXT+1`) and drives state via `NextState(EventRcvFin/FinAck)` or direct Figure 6 mapping: `ESTABLISHED→CLOSE-WAIT`, `FIN-WAIT-1` (`FIN+ACK` where `ack==SND.NXT` → `TIME-WAIT` else `CLOSING`), `FIN-WAIT-2→TIME-WAIT`, `CLOSE-WAIT` stays, `CLOSING→TIME-WAIT` on ACK, `TIME-WAIT` restart timer per p.72, `LAST-ACK→CLOSED` on `ACK`. Each `TIME-WAIT` entry arms `TCB.EnterTimeWait(now,Default2MSL)` via `time.Now()` (tests override via injected `TimeWaitUntil`).
- **TCB TIME-WAIT** (`pkg/tcp/tcb.go` phase 5): new `TimeWaitUntil time.Time`, `EnterTimeWait(now,2MSL)` sets `State=TIME-WAIT`, `TimeWaitUntil=now+2MSL`, `TimeWaitExpired(now)` (`!now.Before(deadline)`), `CloseTimeWait(now)` → `CLOSED` (RFC 793 p.42 2MSL). Helpers `TimeWaitTimeout(tcb,now)` for stack. Deterministic: tests inject `now` without sleeps, wait for `go test -race` green.

### Data path FIN (`pkg/tcp/data.go` phase 5)

- **Recv FIN** (RFC 793 p.69-70): after in-order reassembly, `FIN` advances `RCV.NXT` by 1 and drives `NextState(EventRcvFin/FinAck)` matching control mapping (`ESTABLISHED→CLOSE-WAIT`, `FIN-WAIT-1`/`FIN-WAIT-2`→`TIME-WAIT`/`CLOSING`, etc.), arming `EnterTimeWait` via `time.Now()` for `TIME-WAIT`. Out-of-order `FIN` buffered as data; duplicate `FIN` (`SEQ<RCV.NXT`) returns duplicate ACK (p.69). `SYN` in `ESTABLISHED` still errors `ErrSegmentUnexpected`.

### Out of scope (phase 5)

- Full `TIME-WAIT` restart on duplicate `FIN` + retransmission of final `ACK` loop beyond single `EnterTimeWait` (covers p.72 restart, not full retransmit of ACK).
- Keepalive, linger, half-close `SHUTDOWN` semantics — graceful `FIN`/`TIME-WAIT` and `RST` abort only.
- `CLOSED` RST generation for stray segments beyond returning `ErrTCBClosed` (caller should build RST per p.65 `Seq=0 Ack=SEG.SEQ+SEG.LEN`).

## Phase 6 — Integration (deprecation + example)

### Phase 6a — Deprecation (phase 6a commit)

- **Legacy `server/` (`server/server.go:13`, `server/types.go:3`) and `main.go:35`** are deprecated (RFC 793 reset per AGENTS.md §1). Retained solely for `go vet`/`go test` build compatibility; package docs now carry `Deprecated: use pkg/tcp` and `main.go` carries `Deprecated: use cmd/example`. No behavior change — `Server` still builds via `net.Listen("tcp")` for the old demo, but new code must use `pkg/tcp`.
- **README.md** updated to mark phases 0–5 ✅ Done, phase 6 split into 6a (deprecation) / 6b (example+tests next), and to note `server/` as deprecated and `cmd/example` as the replacement.

### Phase 6b — Integration example + loopback tests (this commit)

- **Example** (`cmd/example/main.go`): tiny CLI exercising the stack without privileged sockets (`go run ./cmd/example`): `PassiveOpen` LISTEN → `ActiveOpen` SYN-SENT, `Stack.Deliver` handshake (SYN→SYN-ACK→ACK) to `ESTABLISHED`, `Send` with `retransmit.Queue` (MSS 10, SND.WND flow control, PSH|ACK), `Recv` with reassembly (in-order + OOO buffering, duplicate ACK), graceful 4-way close (`Close` FIN-WAIT-1 → Recv CLOSE-WAIT → Close LAST-ACK → Recv TIME-WAIT → HandleSegment CLOSED) and `TIME-WAIT 2MSL` expiry via `EnterTimeWait/CloseTimeWait` (RFC 793 §3.4/§3.9, Default2MSL). All segments carry `RcvWnd` and use wrapping-aware `IsSegmentAcceptable`/`AckAcceptable`.
- **Loopback tests** (`pkg/tcp/loopback_test.go`): `TestLoopbackFullFlow` (handshake `Stack.Deliver` SYN→SYN-ACK→ACK to ESTABLISHED, data 250 bytes MSS 100 reassembled via `Send`/`Recv` + `retransmit.Queue` Ack, OOO buffering, 4-way close + `2MSL` deterministic `10ms` expiry), `TestLoopbackStackDemux` (4-tuple exact vs `LISTEN` fallback), `TestIntegrationExampleRuns` (header marshal+`VerifyChecksum` golden). No `net.Listen` / raw sockets, no sleeps (fake clock for RTO/TIME-WAIT), deterministic `go test -race` green.

## References

- RFC 793 https://datatracker.ietf.org/doc/html/rfc793
- RFC 1122 §4.2 https://datatracker.ietf.org/doc/html/rfc1122#page-84
- RFC 1071 Computing the Internet Checksum
