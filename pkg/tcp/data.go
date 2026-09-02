// Package tcp — data path per RFC 793 §3.3-§3.9 (send/receive, ack, window).
// The TCB remains owned by a single goroutine; retransmit.Queue is
// likewise goroutine-local. No sleeps are used in the data path so
// tests are deterministic.
package tcp

import (
	"errors"
	"fmt"

	"github.com/jonandonigv/tcp/pkg/retransmit"
)

// Data-path sentinel errors.
var (
	ErrNotConnected       = errors.New("tcp: not connected")
	ErrSegmentOutOfWindow = errors.New("tcp: segment outside window")
	ErrZeroWindow         = errors.New("tcp: zero window")
)

// DefaultMSS is the default maximum segment size when no option negotiated
// (RFC 793 §3.7: 536 bytes; Ethernet MSS 1460 is common — use 1460 for tests).
const DefaultMSS = 1460

// IsSegmentAcceptable checks RFC 793 §3.3 p.25-26 / §3.9 p.69 acceptability.
//
// A segment is acceptable if:
//   SEG.SEQ in [RCV.NXT, RCV.NXT+RCV.WND) OR SEG.SEQ+SEG.LEN in window
//   For zero-length segments, SEG.SEQ == RCV.NXT is required.
// For the MVP we only consider payload length (SYN/FIN would add 1).
func IsSegmentAcceptable(tcb *TCB, hdr *Header, payloadLen int) bool {
	segLen := payloadLen
	// SYN and FIN each consume one sequence number (RFC 793 p.25).
	if hdr.HasFlag(FlagSYN) {
		segLen++
	}
	if hdr.HasFlag(FlagFIN) {
		segLen++
	}
	if segLen == 0 {
		// Zero-length segment must have SEQ == RCV.NXT (RFC 793 p.69).
		// Also acceptable if window is 0 and SEQ == RCV.NXT (probe).
		return hdr.SeqNum == tcb.RcvNxt
	}
	// Any byte in window makes segment acceptable? RFC 793 p.69 first check
	// and p.25 window description says the segment is acceptable if
	// SEG.SEQ is in window OR segment overlaps window.
	// For phase 4 we require at least the first byte in window to avoid
	// complexity of trimming overlapping segments; tests use in-window.
	if segLen == 0 {
		return false
	}
	seq := hdr.SeqNum
	end := seq + uint32(segLen) // wraps naturally
	// Check if seq in [RCV.NXT, RCV.NXT+Wnd)
	if tcb.InWindow(seq) {
		return true
	}
	// Also check overlap: segment end-1 in window (e.g., segment starts
	// before window but extends into it). RFC 793 p.69 allows trimming.
	// We treat overlap as acceptable for the trimming caller.
	// Compute last byte seq: end-1
	last := end - 1
	if tcb.InWindow(last) {
		return true
	}
	// Wrap-aware inclusive check: if window wraps, segment spanning wrap may still be ok.
	// With the two checks above we cover contiguous window (window <2^31).
	return false
}

// Send segments user data respecting MSS and SND.WND per RFC 793 §3.7.
// The TCB must be synchronized (ESTABLISHED, CLOSE-WAIT). It advances
// SND.NXT, enqueues each segment into q (retransmit.Queue), and returns
// the headers (Seq=SND.NXT prior to advance, Ack=RCV.NXT, Flags=PSH|ACK).
// If SND.WND == 0 the connection is zero-window and no data is sent
// (caller should probe — phase 4 returns ErrZeroWindow). Segmentation
// follows RFC 793 p.42 Nagle not implemented, just MSS chunking.
//
// mss <=0 uses DefaultMSS. data may be empty (no-op).
func Send(tcb *TCB, q *retransmit.Queue, data []byte, mss int) ([]*Header, error) {
	if !tcb.IsSynchronized() {
		return nil, fmt.Errorf("%w: state %v", ErrNotConnected, tcb.State)
	}
	if len(data) == 0 {
		return nil, nil
	}
	if mss <= 0 {
		mss = DefaultMSS
	}
	if tcb.SndWnd == 0 {
		return nil, ErrZeroWindow
	}
	// Usable window = SND.WND - outstanding (SND.NXT - SND.UNA)
	outstanding := tcb.SndNxt - tcb.SndUna // wraps naturally
	usable := uint32(tcb.SndWnd) - outstanding
	if usable == 0 {
		return nil, ErrZeroWindow
	}
	// Limit total bytes to usable window
	if uint32(len(data)) > usable {
		data = data[:usable]
	}

	var hdrs []*Header
	off := 0
	for off < len(data) {
		chunkLen := mss
		if off+chunkLen > len(data) {
			chunkLen = len(data) - off
		}
		chunk := data[off : off+chunkLen]
		h := &Header{
			SrcPort: tcb.LocalPort,
			DstPort: tcb.RemotePort,
			SeqNum:  tcb.SndNxt,
			AckNum:  tcb.RcvNxt,
			Flags:   FlagPSH | FlagACK,
			Window:  tcb.RcvWnd,
		}
		hdrs = append(hdrs, h)
		if q != nil {
			q.Enqueue(h.SeqNum, chunk)
		}
		tcb.AdvanceSndNxt(uint32(chunkLen))
		off += chunkLen
	}
	return hdrs, nil
}

// Recv processes an incoming data segment per RFC 793 §3.9 p.69-70.
// It performs:
//  1. Segment acceptability (window) check — out-of-window → send ACK with RCV.NXT (duplicate ACK) per p.69.
//  2. ACK validation — ack in [SND.UNA, SND.NXT] else drop per p.69.
//  3. Window update — SND.WND ← SEG.WND, WL1/WL2 per p.70.
//  4. Duplicate detection / in-order delivery — if SEQ==RCV.NXT deliver, else buffer Ooo.
//  5. Returns (delivered payload, ack header to send). Delivered is contiguous
//     bytes starting at prior RCV.NXT; ack is an ACK (Seq=SND.NXT Ack=RCV.NXT)
//     whenever a segment was acceptable (or duplicate ACK for unacceptable).
//
// The TCB must be synchronized; LISTEN/SYN-* use control.go HandleSegment.
// SYN/FIN flags on data segments are handled as 1-byte consumption beyond
// payload (RFC 793 p.25) but urgent/PSH are carried opaquely until phase 5.
func Recv(tcb *TCB, q *retransmit.Queue, hdr *Header, payload []byte) (delivered []byte, ack *Header, err error) {
	if !tcb.IsSynchronized() {
		return nil, nil, fmt.Errorf("%w: state %v", ErrNotConnected, tcb.State)
	}
	// RST in established terminates (RFC 793 p.68) — handled here for data path.
	if hdr.HasFlag(FlagRST) {
		tcb.State = StateClosed
		return nil, nil, ErrConnectionReset
	}

	// 1. Acceptability
	if !IsSegmentAcceptable(tcb, hdr, len(payload)) {
		// RFC 793 p.69: send ACK <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
		ack = BuildAck(tcb)
		return nil, ack, ErrSegmentOutOfWindow
	}

	// 2. ACK processing if ACK flag set (RFC 793 p.70)
	if hdr.HasFlag(FlagACK) {
		if !tcb.AckAcceptable(hdr.AckNum) {
			// Duplicate/unacceptable ACK — drop per p.69 but still ack? For MVP drop.
			// We return duplicate ACK to be safe.
			ack = BuildAck(tcb)
			return nil, ack, ErrAckNotAcceptable
		}
		// Valid ACK — advance SND.UNA, prune retransmit queue, update window.
		_ = tcb.UpdateSndUna(hdr.AckNum)
		if q != nil {
			q.Ack(hdr.AckNum)
		}
		// Window update per RFC 793 p.70: if SEG.SEQ == SND.WL1 and SEG.ACK >= SND.WL2
		// or SEG.SEQ > SND.WL1, update. Use wrapping comparisons: SEQ > WL1 or SEQ==WL1 && ACK >= WL2.
		shouldUpdate := false
		if int32(hdr.SeqNum-tcb.SndWL1) > 0 {
			shouldUpdate = true
		} else if hdr.SeqNum == tcb.SndWL1 && int32(hdr.AckNum-tcb.SndWL2) >= 0 {
			shouldUpdate = true
		}
		if shouldUpdate {
			tcb.SndWnd = hdr.Window
			tcb.SndWL1 = hdr.SeqNum
			tcb.SndWL2 = hdr.AckNum
		} else {
			// Still update WND if ack advances but window check fails? RFC 793 says ignore.
			// Keep old WND.
		}
	}

	// 3. Data / reassembly
	if len(payload) == 0 && !hdr.HasFlag(FlagFIN) {
		// Pure ACK — no data to deliver, but we still send ACK if needed? No.
		// Return no delivered, no ack (ack was consumed). For keepalive we could send ack.
		return nil, nil, nil
	}

	seq := hdr.SeqNum
	// Handle SYN flag on data path? Should not happen in ESTABLISHED except simultaneous, but count.
	if hdr.HasFlag(FlagSYN) {
		// SYN consumes 1 beyond payload? But in established, duplicate SYN is old — treat as error.
		// For now adjust seq for payload after SYN?
		// RFC 793 p.69: SYN present in ESTABLISHED is error → drop.
		ack = BuildAck(tcb)
		return nil, ack, ErrSegmentUnexpected
	}

	// In-order?
	if seq == tcb.RcvNxt {
		delivered = append(delivered, payload...)
		tcb.AdvanceRcvNxt(uint32(len(payload)))
		// Try to reassemble buffered segments that become contiguous.
		for {
			if next, ok := tcb.Reassembly[tcb.RcvNxt]; ok {
				delete(tcb.Reassembly, tcb.RcvNxt)
				delivered = append(delivered, next...)
				tcb.AdvanceRcvNxt(uint32(len(next)))
			} else {
				break
			}
		}
		// Handle FIN (1 seq) after data
		if hdr.HasFlag(FlagFIN) {
			tcb.AdvanceRcvNxt(1)
			// State transition for FIN will be handled by control.go phase 5;
			// for now remain ESTABLISHED and ACK.
		}
		ack = BuildAck(tcb)
		return delivered, ack, nil
	}

	// Out-of-order or duplicate: if seq < RCV.NXT it's duplicate (already acked) — send duplicate ACK.
	if int32(seq-tcb.RcvNxt) < 0 {
		ack = BuildAck(tcb)
		return nil, ack, nil // duplicate
	}

	// Future segment within window but not next — buffer.
	if tcb.Reassembly == nil {
		tcb.Reassembly = make(map[uint32][]byte)
	}
	// Avoid duplicate buffering: if already buffered, drop.
	if _, exists := tcb.Reassembly[seq]; !exists {
		cp := make([]byte, len(payload))
		copy(cp, payload)
		tcb.Reassembly[seq] = cp
	}
	ack = BuildAck(tcb)
	// Also handle FIN in out-of-order segment? Buffer FIN as well but for MVP just ACK.
	return nil, ack, nil
}

// NeedsAck reports whether an incoming acceptable segment should generate an ACK.
// For MVP every acceptable data segment generates an ACK (delayed ACK not
// implemented).
func NeedsAck() bool { return true }
