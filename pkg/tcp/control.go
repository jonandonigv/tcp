// Package tcp — connection control per RFC 793 §3.4 (handshake) and §3.8 (user OPEN).
// Control is driven by the TCB's owning goroutine; no shared state is
// mutated concurrently (see state.go/tcb.go).
package tcp

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jonandonigv/tcp/pkg/retransmit"
)

// Sentinel errors for handshake control.
var (
	ErrSegmentUnexpected = errors.New("tcp: unexpected segment for state")
	ErrConnectionReset   = errors.New("tcp: connection reset")
	ErrAckNotAcceptable  = errors.New("tcp: ack not acceptable")
	ErrInvalidClose      = errors.New("tcp: invalid close for state")
)

// Default2MSL is the TIME-WAIT duration (RFC 793 §3.2 p.42: 2*MSL, MSL=2min.
// Implementations often use 60s; we default to 60s for tests with short
// injectable clock, production may use 120s (2*60s) or 240s (2*120s).
const Default2MSL = 60 * time.Second

// ActiveOpen creates a TCB in SYN-SENT and returns the initial SYN segment
// per RFC 793 §3.4 p.33 active OPEN. The SYN consumes one sequence number
// (RFC 793 p.25). Caller supplies ISS for deterministic tests; production
// should use a clock-based ISN (RFC 793 p.27). rcvWnd==0 uses DefaultRcvWindow.
// The returned Header is ready to MarshalWithChecksum (SeqNum=ISS, Flags=SYN).
func ActiveOpen(localAddr netip.Addr, localPort uint16, remoteAddr netip.Addr, remotePort uint16, iss uint32, rcvWnd uint16) (*TCB, *Header, error) {
	// RFC 793 §3.8 p.33 — active OPEN from CLOSED → SYN-SENT
	tcb, err := NewTCB(localAddr, localPort, remoteAddr, remotePort, StateSynSent, iss, rcvWnd)
	if err != nil {
		return nil, nil, err
	}
	// SYN consumes one seq: SND.NXT is already ISS+1 per NewTCB for SYN_SENT.
	h := &Header{
		SrcPort: localPort,
		DstPort: remotePort,
		SeqNum:  iss,
		AckNum:  0,
		Flags:   FlagSYN,
		Window:  tcb.RcvWnd,
	}
	return tcb, h, nil
}

// PassiveOpen creates a LISTEN TCB per RFC 793 §3.8 p.33 passive OPEN.
// RemoteAddr/Port remain unspecified until a SYN arrives and a child
// TCB is cloned (see HandleListenSegment).
func PassiveOpen(localAddr netip.Addr, localPort uint16, rcvWnd uint16) (*TCB, error) {
	return NewListenTCB(localAddr, localPort, rcvWnd)
}

// HandleListenSegment processes a segment arriving at a LISTEN TCB.
// Per RFC 793 §3.9 p.65-66:
//
//   1. check for RST — ignore
//   2. check for ACK — ignore (RFC 793 says ignore ACK in LISTEN; some
//      stacks send RST, but we drop to avoid amplification)
//   3. check for SYN — if present, clone a child TCB in SYN-RECEIVED and
//      return a SYN-ACK reply; otherwise drop.
//
// The LISTEN TCB itself stays in LISTEN. The child ISS is supplied by
// caller for determinism. On success the child is in SYN-RECEIVED with
// IRS=seg.SeqNum, RCV.NXT=IRS+1, SND.UNA/SND.NXT set from iss, and a
// SYN-ACK header (SYN|ACK, Seq=iss, Ack=irs+1).
func HandleListenSegment(listen *TCB, seg *Header, iss uint32) (*TCB, *Header, error) {
	if listen.State != StateListen {
		return nil, nil, fmt.Errorf("%w: HandleListenSegment requires LISTEN, got %v", ErrInvalidState, listen.State)
	}
	// RFC 793 §3.9 p.65 first steps for LISTEN
	if seg.HasFlag(FlagRST) {
		// drop RST in LISTEN
		return nil, nil, nil
	}
	if seg.HasFlag(FlagACK) {
		// In LISTEN, any ACK is unexpected — drop (no RST to avoid reflection).
		// Some implementations send RST; we follow strict RFC 793 p.65.
		return nil, nil, nil
	}
	if !seg.HasFlag(FlagSYN) {
		// No SYN — drop
		return nil, nil, nil
	}
	// SYN present — clone child (RFC 793 p.65-66)
	// Derive remote 4-tuple from source port if available; addresses must
	// be supplied by the stack demux layer. For the skeleton we synthesize
	// remote Addr as listen's LocalAddr if zero? Caller should fill after.
	// We use unspecified remote addr if not known; tests fill RemoteAddr via
	// caller-provided listen.RemoteAddr placeholder or we keep zero.
	// For deterministic tests the control layer passes peer addr via
	// listen's pending remote — instead require caller to pass peer addr?
	// Simplify: use zero addr + seg ports; demux will fixup.
	remoteAddr := listen.RemoteAddr // may be zero; caller overrides if needed
	remotePort := seg.SrcPort
	// If the listen TCB has no remote addr configured, keep unspecified;
	// the stack can set it. For tests we honour listen's RemoteAddr if valid
	// else synthesize from header.
	if !remoteAddr.IsValid() {
		remoteAddr = netip.Addr{} // remains invalid; test will assert ports only
	}
	child, err := listen.CloneForChild(remoteAddr, remotePort, iss, seg.SeqNum)
	if err != nil {
		return nil, nil, err
	}
	// Window update from peer's advertised window (RFC 793 p.66)
	child.SndWnd = seg.Window

	reply := &Header{
		SrcPort: child.LocalPort,
		DstPort: child.RemotePort,
		SeqNum:  iss,
		AckNum:  seg.SeqNum + 1, // RCV.NXT
		Flags:   FlagSYN | FlagACK,
		Window:  child.RcvWnd,
	}
	return child, reply, nil
}

// HandleListenSegmentWithAddrs is the address-aware variant of HandleListenSegment.
// It takes the peer's IP addresses from the stack demux (IP pseudo-header).
// Prefer this over HandleListenSegment when addresses are available.
func HandleListenSegmentWithAddrs(listen *TCB, seg *Header, peerAddr netip.Addr, iss uint32) (*TCB, *Header, error) {
	if listen.State != StateListen {
		return nil, nil, fmt.Errorf("%w: HandleListenSegment requires LISTEN, got %v", ErrInvalidState, listen.State)
	}
	if seg.HasFlag(FlagRST) {
		return nil, nil, nil
	}
	if seg.HasFlag(FlagACK) {
		return nil, nil, nil
	}
	if !seg.HasFlag(FlagSYN) {
		return nil, nil, nil
	}
	child, err := listen.CloneForChild(peerAddr, seg.SrcPort, iss, seg.SeqNum)
	if err != nil {
		return nil, nil, err
	}
	child.SndWnd = seg.Window
	reply := &Header{
		SrcPort: child.LocalPort,
		DstPort: child.RemotePort,
		SeqNum:  iss,
		AckNum:  seg.SeqNum + 1,
		Flags:   FlagSYN | FlagACK,
		Window:  child.RcvWnd,
	}
	return child, reply, nil
}

// HandleSegment processes a segment for a non-LISTEN TCB (SYN-SENT,
// SYN-RECEIVED, ESTABLISHED and beyond) per RFC 793 §3.9 p.66-69.
// It validates SEQ/ACK, updates TCB (RCV.NXT, SND.UNA/WND), drives the
// state machine, and returns a reply header (ACK, SYN-ACK, or RST) if
// one should be sent. A nil reply means drop/consume.
//
// Coverage for phase 3-5:
//   SYN-SENT  : RST, SYN, SYN+ACK dispatch (RFC 793 p.36)
//   SYN-RECEIVED: ACK dispatch, RST
//   ESTABLISHED/CLOSE-WAIT etc.: ACK validation, FIN/CLOSE handling, RST→CLOSED
func HandleSegment(tcb *TCB, seg *Header) (*Header, error) {
	if tcb.State == StateListen {
		return nil, fmt.Errorf("%w: HandleSegment called on LISTEN; use HandleListenSegment", ErrInvalidState)
	}
	// RFC 793 §3.9 p.66 RST handling — must be checked before SYN/ACK
	if seg.HasFlag(FlagRST) {
		return handleRST(tcb, seg)
	}

	switch tcb.State {
	case StateSynSent:
		return handleSynSent(tcb, seg)
	case StateSynReceived:
		return handleSynReceived(tcb, seg)
	case StateEstablished, StateFinWait1, StateFinWait2, StateCloseWait, StateClosing, StateLastAck, StateTimeWait:
		// Phase 4/5: handle FIN/ACK for graceful close per RFC 793 §3.9 p.70-72.
		// ACK validation first (RFC 793 p.69).
		if seg.HasFlag(FlagACK) && !tcb.AckAcceptable(seg.AckNum) {
			return nil, fmt.Errorf("%w: ack %d not in [%d,%d] state %v", ErrAckNotAcceptable, seg.AckNum, tcb.SndUna, tcb.SndNxt, tcb.State)
		}
		// Process ACK (advance UNA) if present.
		if seg.HasFlag(FlagACK) {
			_ = tcb.UpdateSndUna(seg.AckNum)
			// Window update per RFC 793 p.70 similar to data path; omitted for
			// control path unless needed for close FIN ack. Keep SND.WND fresh.
			// Caller via data.go handles WL1/WL2; control just updates una.
		}
		// FIN handling — consume 1 seq and drive state machine (RFC 793 p.70-71).
		if seg.HasFlag(FlagFIN) {
			return handleFin(tcb, seg)
		}
		// Check if our FIN was acked (FIN-WAIT-1 → FIN-WAIT-2 etc.) when ACK arrives without FIN.
		if seg.HasFlag(FlagACK) {
			return handleFinAck(tcb, seg)
		}
		// Pure ACK in ESTABLISHED — no reply.
		return nil, nil
	case StateClosed:
		// RFC 793 p.66: CLOSED → send RST for non-RST segment.
		// Caller should send RST reply with Seq=0 Ack=SEG.SEQ+SEG.LEN.
		// For skeleton return error indicating reset needed.
		return nil, ErrTCBClosed
	default:
		return nil, fmt.Errorf("%w: state %v not handled", ErrInvalidState, tcb.State)
	}
}

// handleFin processes an incoming FIN per RFC 793 §3.9 p.70-71.
// It advances RCV.NXT by 1 (FIN consumes one, RFC 793 p.25), sends ACK,
// and drives the state machine via the event table (ESTABLISHED→CLOSE-WAIT,
// FIN-WAIT-1→CLOSING/TIME-WAIT, FIN-WAIT-2→TIME-WAIT, CLOSE-WAIT stays, etc.).
func handleFin(tcb *TCB, seg *Header) (*Header, error) {
	// Acceptability: segment must be in-window (caller validated via IsSegmentAcceptable
	// or via data path; here we ensure SEQ == RCV.NXT for in-order FIN, else out-of-window
	// would have been handled earlier. For MVP require SEQ == RCV.NXT).
	// We still advance RCV.NXT even if out-of-order? For simultaneous close we may get FIN ahead.
	// For phase 5 we handle in-order FIN only; out-of-order FIN buffered as in data path.
	// Use Recv's logic for true reassembly; control's handleFin is for states where
	// no data payload expected (close states). Keep simple: advance RCV.NXT if equal.
	payloadLen := 0 // control path has no payload; data path handles payload+FIN via Recv
	_ = payloadLen
	// If segment carries ACK+FIN together, need to distinguish CLOSING vs TIME-WAIT
	hasAck := seg.HasFlag(FlagACK)
	// Advance RCV.NXT by 1 for FIN (RFC 793 p.25) if seq matches expected.
	if seg.SeqNum == tcb.RcvNxt {
		tcb.AdvanceRcvNxt(1)
	} else if IsSegmentAcceptable(tcb, seg, 0) {
		// Out-of-window but acceptable overlap — still advance if first byte in window.
		// For MVP just advance to seg.SeqNum+1 if acceptable.
		if tcb.InWindow(seg.SeqNum) {
			tcb.RcvNxt = seg.SeqNum + 1
		}
	}
	// State transition per RFC 793 Fig.6
	prev := tcb.State
	switch prev {
	case StateEstablished:
		tcb.State = StateCloseWait
	case StateFinWait1:
		if hasAck && seg.AckNum == tcb.SndNxt {
			// Our FIN was acked + peer FIN together → TIME-WAIT (FIN+ACK)
			tcb.State = StateTimeWait
		} else if hasAck {
			// ACK acks our FIN but FIN is separate? Still FIN-WAIT-1 → CLOSING if FIN not yet acked? Check event table
			// FIN-WAIT-1 --RCV_FIN--> CLOSING, --RCV_FINACK--> TIME-WAIT
			// Distinguish by whether ACK acks our FIN (SND.UNA==SND.NXT after update)
			// If our FIN was acked via this segment's ACK, it would be ack==SND.NXT, then FIN+ACK → TIME-WAIT
			// Otherwise CLOSING (simultaneous close)
			// We already did UpdateSndUna above, so check if SND.UNA==SND.NXT
			if tcb.SndUna == tcb.SndNxt {
				tcb.State = StateTimeWait
			} else {
				tcb.State = StateClosing
			}
		} else {
			tcb.State = StateClosing
		}
		// If TIME-WAIT, arm 2MSL timer with now via time.Now (caller may override via EnterTimeWait)
		if tcb.State == StateTimeWait && tcb.TimeWaitUntil.IsZero() {
			tcb.EnterTimeWait(time.Now(), Default2MSL)
		}
	case StateFinWait2:
		tcb.State = StateTimeWait
		if tcb.TimeWaitUntil.IsZero() {
			tcb.EnterTimeWait(time.Now(), Default2MSL)
		}
	case StateCloseWait:
		// Already passive close, receiving FIN again? Should stay CLOSE-WAIT (duplicate) — just ACK.
	case StateClosing:
		// Should not receive another FIN, but if we do, go to TIME-WAIT on ACK
		if hasAck && seg.AckNum == tcb.SndNxt {
			tcb.State = StateTimeWait
			if tcb.TimeWaitUntil.IsZero() {
				tcb.EnterTimeWait(time.Now(), Default2MSL)
			}
		}
	case StateTimeWait:
		// RFC 793 p.72: in TIME-WAIT restart timer on FIN retransmit
		tcb.EnterTimeWait(time.Now(), Default2MSL)
	case StateLastAck:
		// LAST-ACK expects ACK of our FIN, not FIN
	default:
		// For other states, use event table as fallback
		ev := EventRcvFin
		if hasAck {
			ev = EventRcvFinAck
		}
		if nxt, err := NextState(prev, ev); err == nil {
			tcb.State = nxt
			if nxt == StateTimeWait && tcb.TimeWaitUntil.IsZero() {
				tcb.EnterTimeWait(time.Now(), Default2MSL)
			}
		}
	}
	// RFC 793 p.70: send ACK <SEQ=SND.NXT><ACK=RCV.NXT>
	ack := BuildAck(tcb)
	// RST not set, FIN not set in ACK.
	return ack, nil
}

// handleFinAck handles ACK of our FIN without peer FIN (FIN-WAIT-1 → FIN-WAIT-2, etc.)
func handleFinAck(tcb *TCB, seg *Header) (*Header, error) {
	// This is called when segment has ACK but no FIN, and our FIN was acked.
	// Transition per Fig.6: FIN-WAIT-1 --RCV_ACK--> FIN-WAIT-2, CLOSING --RCV_ACK--> TIME-WAIT, LAST-ACK --RCV_ACK--> CLOSED, FIN-WAIT-2 --RCV_FIN--> etc already handled.
	switch tcb.State {
	case StateFinWait1:
		// ACK of our FIN without peer FIN → FIN-WAIT-2
		// Only if ACK == SND.NXT (acks FIN). We already validated AckAcceptable.
		// Check if this ACK acks FIN: after UpdateSndUna, SND.UNA == SND.NXT.
		if tcb.SndUna == tcb.SndNxt {
			tcb.State = StateFinWait2
		}
		return nil, nil
	case StateClosing:
		if tcb.SndUna == tcb.SndNxt {
			tcb.State = StateTimeWait
			if tcb.TimeWaitUntil.IsZero() {
				tcb.EnterTimeWait(time.Now(), Default2MSL)
			}
		}
		return nil, nil
	case StateLastAck:
		if tcb.SndUna == tcb.SndNxt {
			tcb.State = StateClosed
		}
		return nil, nil
	case StateFinWait2, StateEstablished, StateCloseWait, StateTimeWait:
		return nil, nil
	default:
		return nil, nil
	}
}

// handleRST per RFC 793 §3.9 p.68-69.
func handleRST(tcb *TCB, seg *Header) (*Header, error) {
	// RFC 793: In SYN-SENT, RST is acceptable only if ACK field acknowledges our SYN (AckAcceptable).
	// For simplicity we check AckAcceptable where applicable.
	switch tcb.State {
	case StateSynSent:
		if seg.HasFlag(FlagACK) && !tcb.AckAcceptable(seg.AckNum) {
			// Not acceptable — drop
			return nil, nil
		}
		// Acceptable RST — close connection
		tcb.State = StateClosed
		return nil, ErrConnectionReset
	case StateSynReceived, StateEstablished, StateFinWait1, StateFinWait2, StateCloseWait, StateClosing, StateLastAck, StateTimeWait:
		// In synchronized states any RST terminates (RFC 793 p.68).
		tcb.State = StateClosed
		return nil, ErrConnectionReset
	default:
		// In other states ignore RST
		return nil, nil
	}
}

// handleSynSent per RFC 793 p.36 / §3.9 p.66-67.
func handleSynSent(tcb *TCB, seg *Header) (*Header, error) {
	// RFC 793 §3.9 p.67 — SYN-SENT segment acceptability
	// 1. ACK check: if ACK set and not acceptable, drop.
	if seg.HasFlag(FlagACK) {
		if !tcb.AckAcceptable(seg.AckNum) {
			// ACK doesn't ack our SYN — drop
			return nil, fmt.Errorf("%w: ack %d not in [%d,%d]", ErrAckNotAcceptable, seg.AckNum, tcb.SndUna, tcb.SndNxt)
		}
	}
	hasSyn := seg.HasFlag(FlagSYN)
	hasAck := seg.HasFlag(FlagACK)

	switch {
	case hasSyn && hasAck:
		// SYN+ACK — peer acknowledges our SYN and sends its own SYN (RFC 793 p.36 step 5).
		// Validate SYN sequence is acceptable (SYN consumes 1). For SYN-SENT,
		// RCV.NXT is still 0, so we accept any SYN as initial per RFC 793 p.67.
		// Update TCB.
		tcb.IRS = seg.SeqNum
		tcb.RcvNxt = seg.SeqNum + 1 // SYN consumes one (RFC 793 p.25)
		tcb.SndWnd = seg.Window
		tcb.SndWL1 = seg.SeqNum
		tcb.SndWL2 = seg.AckNum
		if err := tcb.UpdateSndUna(seg.AckNum); err != nil {
			return nil, err
		}
		// Transition SYN-SENT → ESTABLISHED (RFC 793 p.36)
		tcb.State = StateEstablished
		// Reply ACK (RFC 793 p.36): Seq=SND.NXT, Ack=RCV.NXT
		reply := &Header{
			SrcPort: tcb.LocalPort,
			DstPort: tcb.RemotePort,
			SeqNum:  tcb.SndNxt, // ISS+1
			AckNum:  tcb.RcvNxt,
			Flags:   FlagACK,
			Window:  tcb.RcvWnd,
		}
		return reply, nil

	case hasSyn && !hasAck:
		// Simultaneous open: peer SYN without ACK (RFC 793 p.32, p.36).
		// Enter SYN-RECEIVED, send SYN-ACK (retransmit our SYN with ACK of peer's SYN).
		tcb.IRS = seg.SeqNum
		tcb.RcvNxt = seg.SeqNum + 1
		tcb.SndWnd = seg.Window
		// SND.NXT already ISS+1, SND.UNA still ISS. Keep.
		tcb.State = StateSynReceived
		reply := &Header{
			SrcPort: tcb.LocalPort,
			DstPort: tcb.RemotePort,
			SeqNum:  tcb.ISS, // retransmit SYN
			AckNum:  tcb.RcvNxt,
			Flags:   FlagSYN | FlagACK,
			Window:  tcb.RcvWnd,
		}
		return reply, nil

	case hasAck && !hasSyn:
		// Lone ACK in SYN-SENT without SYN — could be half-open? Drop.
		// RFC 793 p.67 says if ACK is acceptable and no SYN, still ESTABLISHED? No.
		// For strictness drop.
		return nil, nil

	default:
		// No SYN nor valid SYNACK — drop.
		return nil, nil
	}
}

// handleSynReceived per RFC 793 p.36 / §3.9 p.68.
func handleSynReceived(tcb *TCB, seg *Header) (*Header, error) {
	// RFC 793 §3.9 p.68: In SYN-RECEIVED, check ACK.
	if !seg.HasFlag(FlagACK) {
		// No ACK — discard (retransmit SYN-ACK would happen via RTO, phase 4).
		return nil, nil
	}
	if !tcb.AckAcceptable(seg.AckNum) {
		return nil, fmt.Errorf("%w: ack %d not in [%d,%d]", ErrAckNotAcceptable, seg.AckNum, tcb.SndUna, tcb.SndNxt)
	}
	// Duplicate SYN? If SYN present again, peer retransmitted; resend SYN-ACK.
	if seg.HasFlag(FlagSYN) {
		// SYN+ACK duplicate — already synchronized? But we are still SYN-RECEIVED.
		// Could be retransmit. Reply ACK again? For simplicity remain in SYN-RECEIVED and resend SYN-ACK.
		reply := &Header{
			SrcPort: tcb.LocalPort,
			DstPort: tcb.RemotePort,
			SeqNum:  tcb.ISS,
			AckNum:  tcb.RcvNxt,
			Flags:   FlagSYN | FlagACK,
			Window:  tcb.RcvWnd,
		}
		return reply, nil
	}
	// Valid ACK of our SYN — update and enter ESTABLISHED (RFC 793 p.36).
	if err := tcb.UpdateSndUna(seg.AckNum); err != nil {
		return nil, err
	}
	tcb.SndWnd = seg.Window
	tcb.SndWL1 = seg.SeqNum
	tcb.SndWL2 = seg.AckNum
	tcb.State = StateEstablished
	// No reply needed — ACK is consumed.
	return nil, nil
}

// BuildAck returns an ACK segment for an established TCB (phase 4 helper
// but useful for handshake ACK). Seq=SND.NXT, Ack=RCV.NXT.
func BuildAck(tcb *TCB) *Header {
	return &Header{
		SrcPort: tcb.LocalPort,
		DstPort: tcb.RemotePort,
		SeqNum:  tcb.SndNxt,
		AckNum:  tcb.RcvNxt,
		Flags:   FlagACK,
		Window:  tcb.RcvWnd,
	}
}

// Close initiates graceful close (user CLOSE) per RFC 793 §3.8 p.33 / §3.9 p.71.
// It moves the TCB per Figure 6 and returns the FIN segment to send.
// FIN consumes one sequence (RFC 793 p.25). The segment is enqueued into q
// for retransmission (RTO) and SND.NXT is advanced.
//
// Valid origins: ESTABLISHED → FIN-WAIT-1, CLOSE-WAIT → LAST-ACK,
// SYN-RECEIVED → FIN-WAIT-1 (rare), SYN-SENT is error (use Abort).
func Close(tcb *TCB, q *retransmit.Queue) (*Header, error) {
	var next State
	switch tcb.State {
	case StateEstablished:
		next = StateFinWait1
	case StateCloseWait:
		next = StateLastAck
	case StateSynReceived, StateSynSent:
		// RFC 793 allows CLOSE from SYN-RECEIVED → FIN-WAIT-1
		next = StateFinWait1
	default:
		return nil, fmt.Errorf("%w: CLOSE from %v", ErrInvalidClose, tcb.State)
	}
	if !tcb.State.CanTransitionTo(next) {
		return nil, fmt.Errorf("%w: %v → %v", ErrInvalidTransition, tcb.State, next)
	}
	h := &Header{
		SrcPort: tcb.LocalPort,
		DstPort: tcb.RemotePort,
		SeqNum:  tcb.SndNxt,
		AckNum:  tcb.RcvNxt,
		Flags:   FlagFIN | FlagACK,
		Window:  tcb.RcvWnd,
	}
	// Enqueue for retransmission before advancing SND.NXT (retransmit needs Seq)
	// FIN consumes 1 sequence number (RFC 793 p.25); queue stores 1-byte dummy
	// so Ack(Seq+1) will clear it (RFC 793 p.41).
	if q != nil {
		q.Enqueue(h.SeqNum, []byte{0})
	}
	tcb.AdvanceSndNxt(1) // FIN consumes 1 (RFC 793 p.25)
	tcb.State = next
	return h, nil
}

// Abort initiates abort (user ABORT / RST) per RFC 793 §3.8 p.34.
// It moves to CLOSED and returns an RST segment <SEQ=SND.NXT><CTL=RST>.
// The retransmit queue is cleared. For LISTEN the TCB goes directly to CLOSED.
func Abort(tcb *TCB, q *retransmit.Queue) (*Header, error) {
	// RFC 793 p.34 ABORT: send RST and enter CLOSED.
	if q != nil {
		q.Clear()
	}
	prev := tcb.State
	tcb.State = StateClosed
	tcb.TimeWaitUntil = time.Time{}
	h := &Header{
		SrcPort: tcb.LocalPort,
		DstPort: tcb.RemotePort,
		SeqNum:  tcb.SndNxt,
		AckNum:  0,
		Flags:   FlagRST,
		Window:  0,
	}
	// In TIME-WAIT abort also closes; otherwise normal RST.
	_ = prev
	return h, nil
}

// TimeWaitTimeout checks if a TCB in TIME-WAIT has expired its 2MSL and
// transitions to CLOSED per RFC 793 p.42. now is injected for determinism.
func TimeWaitTimeout(tcb *TCB, now time.Time) bool {
	return tcb.CloseTimeWait(now)
}
