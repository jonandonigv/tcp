// Package tcp — Transmission Control Block per RFC 793 §3.2 p.19-21.
// TCB is owned by a single goroutine (the connection's state machine
// loop) and must be accessed only via channels or while holding the
// connection's mutex. See state.go for concurrency model.
package tcp

import (
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Default receive window advertised by a new TCB (RFC 793 §3.3 Window).
const DefaultRcvWindow uint16 = 65535

// Sentinel errors for TCB.
var (
	ErrTCBClosed          = errors.New("tcp: TCB closed")
	ErrTCBAlreadyExists   = errors.New("tcp: TCB already exists")
	ErrInvalidTCB         = errors.New("tcp: invalid TCB")
	ErrWindowOutOfRange   = errors.New("tcp: window out of range")
	ErrSeqOutOfWindow     = errors.New("tcp: sequence out of window")
)

// TCB holds per-connection state per RFC 793 §3.2 (p.20).
//
// RFC 793 lists the following variables (all in sequence space unless
// noted). Naming follows the spec but uses Go camelCase:
//
//	SND.UNA – send unacknowledged
//	SND.NXT – send next
//	SND.WND – send window (peer's advertised RCV.WND)
//	SND.UP  – send urgent pointer
//	SND.WL1 – segment sequence number used for last window update
//	SND.WL2 – segment acknowledgment number used for last window update
//	ISS     – initial send sequence number
//
//	RCV.NXT – receive next
//	RCV.WND – receive window (our advertised window)
//	RCV.UP  – receive urgent pointer
//	IRS     – initial receive sequence number
//
// Additional bookkeeping: connection 4-tuple, state, buffers, and the
// retransmission queue (phase 4). The TCB lifetime matches the
// state CLOSED → ... → CLOSED; it is created on OPEN and freed on
// close/timeout.
type TCB struct {
	// Identification.
	LocalAddr  netip.Addr
	LocalPort  uint16
	RemoteAddr netip.Addr
	RemotePort uint16

	// State machine.
	State State

	// Send sequence variables — RFC 793 p.20.
	ISS   uint32 // initial send sequence number
	SndUna uint32 // oldest unacknowledged
	SndNxt uint32 // next to send
	SndWnd uint16 // peer window
	SndUp  uint16 // urgent pointer (phase 5; 0 == no urgent)
	SndWL1 uint32 // window update seg seq
	SndWL2 uint32 // window update seg ack

	// Receive sequence variables.
	IRS   uint32 // initial receive sequence number
	RcvNxt uint32 // next expected
	RcvWnd uint16 // our window
	RcvUp  uint16 // urgent pointer

	// Buffers — phase 4 will add segmentation/reassembly. For skeleton
	// they are present but empty; capacity hints for flow control.
	SendBuf []byte // queued for transmission (SND.NXT onward)
	RecvBuf []byte // reassembled in-order (RCV.NXT onward)

	// Retransmission queue — segments sent but not yet ACKed (SND.UNA .. SND.NXT-1).
	// Opaque until retransmit/ package lands (phase 4).
	RetransmitQueue [][]byte // legacy placeholder; phase 4 uses pkg/retransmit.Queue

	// Reassembly buffer for out-of-order segments (phase 4).
	// Key is SEG.SEQ, value is payload bytes. Guarded by TCB goroutine.
	Reassembly map[uint32][]byte

	// TIME-WAIT state (phase 5, RFC 793 §3.2 p.23, 2MSL).
	// When State == TIME-WAIT, TimeWaitUntil is the deadline after which
	// the TCB may be moved to CLOSED (RFC 793 p.42 2MSL). Zero means not in TIME-WAIT.
	TimeWaitUntil time.Time
}

// NewTCB creates a TCB in the given state with the supplied ISS and
// receive window. It mirrors the RFC 793 p.23 initialization steps:
//
//	SND.UNA ← ISS
//	SND.NXT ← ISS+1 for SYN-SENT / SYN-RECEIVED (SYN consumes one seq),
//	         ISS otherwise (phase 3 will advance)
//	SND.WND ← 0 (unknown until peer ACKs)
//	SND.WL1 ← ISS
//	SND.WL2 ← 0
//	RCV.NXT ← 0 (→ IRS+1 after SYN received)
//	RCV.WND ← rcvWnd
//
// The caller supplies ISS explicitly for deterministic tests; production
// code should generate it from a clock/ISN generator (RFC 793 p.27).
// rcvWnd == 0 uses DefaultRcvWindow. Addresses may be invalid (unspecified)
// for a LISTEN TCB that has not yet learned the peer (AGENTS.md §7).
func NewTCB(localAddr netip.Addr, localPort uint16, remoteAddr netip.Addr, remotePort uint16, state State, iss uint32, rcvWnd uint16) (*TCB, error) {
	if _, ok := stateNames[state]; !ok {
		return nil, fmt.Errorf("%w: %v", ErrInvalidState, state)
	}
	if rcvWnd == 0 {
		rcvWnd = DefaultRcvWindow
	}
	t := &TCB{
		LocalAddr:  localAddr,
		LocalPort:  localPort,
		RemoteAddr: remoteAddr,
		RemotePort: remotePort,
		State:      state,
		ISS:        iss,
		SndUna:     iss,
		SndNxt:     iss,
		SndWnd:     0,
		SndWL1:     iss,
		SndWL2:     0,
		IRS:        0,
		RcvNxt:     0,
		RcvWnd:     rcvWnd,
		RcvUp:      0,
		Reassembly: make(map[uint32][]byte),
	}
	// SYN consumes one sequence number (RFC 793 p.25). Advance SND.NXT
	// for states where SYN has already been sent.
	switch state {
	case StateSynSent, StateSynReceived, StateEstablished, StateFinWait1, StateFinWait2, StateCloseWait, StateClosing, StateLastAck, StateTimeWait:
		// For SYN-RECEIVED/ESTABLISHED the SYN has definitely been sent;
		// for earlier states (passive LISTEN) it has not, but this helper
		// is called after the transition, so the caller can override SndNxt
		// if needed. The default for SYN-* is ISS+1.
		if state == StateSynSent || state == StateSynReceived {
			t.SndNxt = iss + 1
		}
	case StateListen, StateClosed:
		// No SYN sent yet — keep SND.NXT == ISS.
	}
	return t, nil
}

// NewListenTCB is a convenience for passive OPEN (RFC 793 §3.8 p.33).
// It creates a TCB in LISTEN; RemoteAddr/Port remain Invalid until a
// SYN arrives and the TCB is cloned into a child in SYN-RECEIVED.
func NewListenTCB(localAddr netip.Addr, localPort uint16, rcvWnd uint16) (*TCB, error) {
	return NewTCB(localAddr, localPort, netip.Addr{}, 0, StateListen, 0, rcvWnd)
}

// IsSynchronized delegates to State.IsSynchronized.
func (t *TCB) IsSynchronized() bool { return t.State.IsSynchronized() }

// InWindow reports whether seq lies inside the current receive window
// [RCV.NXT, RCV.NXT+RCV.WND) per RFC 793 §3.3 p.25. It handles wrapping
// via internal/seq helpers. A zero window always returns false (no data
// acceptable) except for zero-length segments (probe) — callers must
// special-case that in phase 4.
func (t *TCB) InWindow(seq uint32) bool {
	if t.RcvWnd == 0 {
		return seq == t.RcvNxt
	}
	// Need wrapping-aware check: seq ∈ [RcvNxt, RcvNxt+RcvWnd)
	// Use int32-difference helpers via inline equivalent to avoid import
	// cycle; duplicate logic from internal/seq.Between for stdlib-only
	// skeleton. Phase 4 will switch to internal/seq.
	end := t.RcvNxt + uint32(t.RcvWnd)
	// Between(seq, start, end) == GTE && LT
	if int32(seq-t.RcvNxt) < 0 {
		return false
	}
	if int32(seq-end) >= 0 {
		return false
	}
	return true
}

// AckAcceptable reports whether ack lies in [SND.UNA, SND.NXT] inclusive
// of SND.UNA and SND.NXT per RFC 793 §3.3 p.26: "An acknowledgment is
// acceptable if it acknowledges something not yet acknowledged." Wrapping
// aware. Used during segment acceptability checks (phase 3).
func (t *TCB) AckAcceptable(ack uint32) bool {
	// ack ∈ [SND.UNA, SND.NXT] inclusive
	// Convert to half-open [SND.UNA, SND.NXT+1) except wraparound.
	// Special case SND.UNA==SND.NXT: only exact ack is acceptable.
	if t.SndUna == t.SndNxt {
		return ack == t.SndUna
	}
	// Check SND.UNA <= ack <= SND.NXT using wrapping comparisons.
	// LTE(SND.UNA, ack) && LTE(ack, SND.NXT)
	if int32(ack-t.SndUna) < 0 {
		return false
	}
	if int32(ack-t.SndNxt) > 0 {
		return false
	}
	return true
}

// AdvanceRcvNxt advances RCV.NXT by n bytes (typically payload length
// plus SYN/FIN which each consume 1). It mirrors the RCV.NXT update in
// RFC 793 §3.9 p.69 for in-order segments.
func (t *TCB) AdvanceRcvNxt(n uint32) { t.RcvNxt += n }

// AdvanceSndNxt advances SND.NXT by n (phase 4 will call after enqueueing).
func (t *TCB) AdvanceSndNxt(n uint32) { t.SndNxt += n }

// UpdateSndUna advances SND.UNA to ack if ack is acceptable (RFC 793 §3.9
// ACK processing). Returns ErrSeqOutOfWindow if ack is outside [UNA,NXT].
func (t *TCB) UpdateSndUna(ack uint32) error {
	if !t.AckAcceptable(ack) {
		return fmt.Errorf("%w: ack %d not in [%d,%d]", ErrSeqOutOfWindow, ack, t.SndUna, t.SndNxt)
	}
	t.SndUna = ack
	// Prune retransmission queue (phase 4 placeholder).
	return nil
}

// SetState transitions the TCB to next if allowed by the state machine
// (RFC 793 Figure 6). It validates via State.CanTransitionTo and returns
// ErrInvalidTransition on illegal jumps. The caller is responsible for
// side effects (timer start, ISN generation, etc.).
func (t *TCB) SetState(next State) error {
	if !t.State.CanTransitionTo(next) {
		return fmt.Errorf("%w: %v → %v", ErrInvalidTransition, t.State, next)
	}
	t.State = next
	return nil
}

// HandleEvent drives the skeleton event table (state.go:NextState) and
// updates t.State accordingly. It is the entry point used by control.go
// (phase 3) and tests. No I/O is performed.
func (t *TCB) HandleEvent(ev Event) error {
	next, err := NextState(t.State, ev)
	if err != nil {
		return err
	}
	t.State = next
	// Side effects for specific events (ISS/IRS bookkeeping).
	switch ev {
	case EventActiveOpen, EventPassiveOpen:
		// ISS already set at creation; nothing else for skeleton.
	case EventRcvSyn:
		// On RCV_SYN in LISTEN the IRS will be filled by control.go;
		// skeleton just advances RCV.NXT to IRS+1 if IRS !=0.
		if t.IRS != 0 && t.RcvNxt == 0 {
			t.RcvNxt = t.IRS + 1
		}
	case EventRcvSynAck:
		if t.IRS != 0 && t.RcvNxt == 0 {
			t.RcvNxt = t.IRS + 1
		}
	}
	return nil
}

// CloneForChild duplicates a LISTEN TCB into a child SYN-RECEIVED TCB for
// a newly arriving SYN (RFC 793 §3.8 p.34 passive open). The child's
// ISS is generated by the caller, IRS is the peer's ISN.
func (t *TCB) CloneForChild(remoteAddr netip.Addr, remotePort uint16, iss, irs uint32) (*TCB, error) {
	if t.State != StateListen {
		return nil, fmt.Errorf("%w: CloneForChild only from LISTEN, got %v", ErrInvalidState, t.State)
	}
	child, err := NewTCB(t.LocalAddr, t.LocalPort, remoteAddr, remotePort, StateSynReceived, iss, t.RcvWnd)
	if err != nil {
		return nil, err
	}
	child.IRS = irs
	child.RcvNxt = irs + 1 // SYN consumes one (RFC 793 p.25)
	child.SndWnd = 0       // will be set from SYN's Window
	return child, nil
}

// EnterTimeWait moves the TCB to TIME-WAIT and arms the 2MSL timer.
// RFC 793 §3.2 p.23 / p.42: TIME-WAIT lasts 2*MSL (MSL=2min per spec, but
// implementations often use 60s; callers supply the 2MSL duration for
// determinism). now is the current time (injected for tests).
func (t *TCB) EnterTimeWait(now time.Time, twoMSL time.Duration) {
	t.State = StateTimeWait
	t.TimeWaitUntil = now.Add(twoMSL)
}

// TimeWaitExpired reports whether the 2MSL timer has fired (RFC 793 p.42).
// It is deterministic; callers provide now (e.g., fake clock).
func (t *TCB) TimeWaitExpired(now time.Time) bool {
	if t.State != StateTimeWait || t.TimeWaitUntil.IsZero() {
		return false
	}
	return !now.Before(t.TimeWaitUntil)
}

// CloseTimeWait advances TIME-WAIT → CLOSED if expired (RFC 793 p.42).
// Returns true if transition occurred.
func (t *TCB) CloseTimeWait(now time.Time) bool {
	if t.TimeWaitExpired(now) {
		t.State = StateClosed
		t.TimeWaitUntil = time.Time{}
		return true
	}
	return false
}

// String returns a debug summary.
func (t *TCB) String() string {
	return fmt.Sprintf("TCB{%v %v:%d→%v:%d iss=%d irs=%d snd[una=%d nxt=%d wnd=%d] rcv[nxt=%d wnd=%d] state=%v}",
		t.LocalAddr, t.LocalAddr, t.LocalPort, t.RemoteAddr, t.RemotePort, t.ISS, t.IRS, t.SndUna, t.SndNxt, t.SndWnd, t.RcvNxt, t.RcvWnd, t.State)
}
