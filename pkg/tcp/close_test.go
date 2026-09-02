package tcp

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jonandonigv/tcp/pkg/retransmit"
)

func establishedForClose() *TCB {
	local := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("10.0.0.2")
	tcb, _ := NewTCB(local, 12345, remote, 80, StateEstablished, 1000, 4096)
	tcb.ISS = 1000
	tcb.SndUna = 1001
	tcb.SndNxt = 1001
	tcb.SndWnd = 8192
	tcb.IRS = 2000
	tcb.RcvNxt = 2001
	tcb.RcvWnd = 4096
	tcb.Reassembly = make(map[uint32][]byte)
	return tcb
}

func TestCloseEstablishedToFinWait1(t *testing.T) {
	tcb := establishedForClose()
	q := retransmit.NewQueue(nil)
	fin, err := Close(tcb, q)
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	if tcb.State != StateFinWait1 {
		t.Errorf("state %v want FIN-WAIT-1", tcb.State)
	}
	if fin.Flags != FlagFIN|FlagACK {
		t.Errorf("FIN flags %06b want FIN|ACK", fin.Flags)
	}
	if fin.SeqNum != 1001 {
		t.Errorf("Seq %d want 1001", fin.SeqNum)
	}
	if tcb.SndNxt != 1002 {
		t.Errorf("SndNxt %d want 1002", tcb.SndNxt)
	}
	if q.Len() != 1 {
		t.Errorf("queue len %d want 1", q.Len())
	}
	// FIN consumes 1, Ack(1002) should clear
	if n := q.Ack(1002); n != 1 {
		t.Errorf("Ack FIN n %d want 1", n)
	}
}

func TestCloseCloseWaitToLastAck(t *testing.T) {
	tcb := establishedForClose()
	tcb.State = StateCloseWait
	q := retransmit.NewQueue(nil)
	fin, err := Close(tcb, q)
	if err != nil {
		t.Fatalf("Close CLOSE-WAIT: %v", err)
	}
	if tcb.State != StateLastAck {
		t.Errorf("state %v want LAST-ACK", tcb.State)
	}
	if fin.Flags != FlagFIN|FlagACK {
		t.Errorf("flags %06b", fin.Flags)
	}
}

func TestCloseInvalidState(t *testing.T) {
	tcb := establishedForClose()
	tcb.State = StateFinWait1
	if _, err := Close(tcb, nil); err == nil {
		t.Error("Close from FIN-WAIT-1 should error")
	}
	tcb2 := establishedForClose()
	tcb2.State = StateClosed
	if _, err := Close(tcb2, nil); err == nil {
		t.Error("Close from CLOSED should error")
	}
}

func TestAbort(t *testing.T) {
	tcb := establishedForClose()
	q := retransmit.NewQueue(nil)
	q.Enqueue(1001, []byte("data"))
	rst, err := Abort(tcb, q)
	if err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if tcb.State != StateClosed {
		t.Errorf("state %v want CLOSED", tcb.State)
	}
	if !rst.HasFlag(FlagRST) {
		t.Errorf("RST flag missing")
	}
	if !q.Empty() {
		t.Error("queue should be cleared")
	}
	// Abort from TIME-WAIT also closes
	tcb2 := establishedForClose()
	tcb2.State = StateTimeWait
	tcb2.EnterTimeWait(time.Now(), time.Second)
	Abort(tcb2, nil)
	if tcb2.State != StateClosed || !tcb2.TimeWaitUntil.IsZero() {
		t.Error("Abort should clear TIME-WAIT")
	}
}

func TestRecvFIN_EstablishedToCloseWait(t *testing.T) {
	tcb := establishedForClose()
	q := retransmit.NewQueue(nil)
	hdr := &Header{SrcPort: 80, DstPort: 12345, SeqNum: 2001, AckNum: 1001, Flags: FlagFIN | FlagACK, Window: 4096}
	delivered, ack, err := Recv(tcb, q, hdr, nil)
	if err != nil {
		t.Fatalf("Recv FIN: %v", err)
	}
	if tcb.State != StateCloseWait {
		t.Errorf("state %v want CLOSE-WAIT", tcb.State)
	}
	if tcb.RcvNxt != 2002 {
		t.Errorf("RcvNxt %d want 2002", tcb.RcvNxt)
	}
	if ack == nil || ack.AckNum != 2002 {
		t.Errorf("ack %+v want Ack 2002", ack)
	}
	if len(delivered) != 0 {
		t.Errorf("FIN with no payload delivered %d", len(delivered))
	}
}

func TestGracefulCloseFourWay(t *testing.T) {
	// Active (A) ESTABLISHED, Passive (B) ESTABLISHED ; A Close → FIN, B recv FIN → CLOSE-WAIT, B Close → FIN, A recv FIN-ACK etc → TIME-WAIT → CLOSED
	localA := netip.MustParseAddr("10.0.0.1")
	remoteB := netip.MustParseAddr("10.0.0.2")
	a := establishedForClose()
	// fix addrs
	a.LocalAddr = localA
	a.RemoteAddr = remoteB
	b := establishedForClose()
	b.LocalAddr = remoteB
	b.RemoteAddr = localA
	b.LocalPort = 80
	b.RemotePort = 12345
	// Sync up seq: A ISS 1000 SYN acked => SND 1001, B IRS 2000 => RCV 2001; B ISS 2000 => SND 2001, A IRS 2000? Actually symmetric but for test we reuse.
	// Align both to same values for simplicity: A's RcvNxt 2001 corresponds to B's SndNxt 2001 etc.
	b.ISS = 2000
	b.SndUna = 2001
	b.SndNxt = 2001
	b.SndWnd = 8192
	b.IRS = 1000
	b.RcvNxt = 1001
	// Wait A and B both have mirrored ? Let's reset to consistent:
	a.SndUna = 1001
	a.SndNxt = 1001
	a.RcvNxt = 2001
	b.SndUna = 2001
	b.SndNxt = 2001
	b.RcvNxt = 1001

	qa := retransmit.NewQueue(nil)
	qb := retransmit.NewQueue(nil)

	// A active close -> FIN-WAIT-1, FIN Seq 1001
	finA, _ := Close(a, qa)
	if a.State != StateFinWait1 || finA.SeqNum != 1001 {
		t.Fatalf("A Close failed %v %+v", a.State, finA)
	}
	// B receives FIN (1001) in ESTABLISHED -> CLOSE-WAIT, ack 1002, RcvNxt 1002
	delivered, ackB, _ := Recv(b, qb, finA, nil)
	if b.State != StateCloseWait || b.RcvNxt != 1002 {
		t.Fatalf("B after FIN state %v RcvNxt %d delivered %q", b.State, b.RcvNxt, delivered)
	}
	if ackB.AckNum != 1002 {
		t.Errorf("B ack %d want 1002", ackB.AckNum)
	}
	// Simulate A receives ACK of its FIN (1002) without peer FIN -> FIN-WAIT-2
	// ackB is pure ACK (Seq 2001 Ack 1002) — deliver to A
	_, _, _ = Recv(a, qa, ackB, nil)
	// But A is still FIN-WAIT-1; HandleSegment would move to FIN-WAIT-2 on ACK.
	// Our Recv's ACK processing doesn't move FIN-WAIT-1→FIN-WAIT-2; control does.
	// Simulate via HandleSegment
	if a.State == StateFinWait1 {
		// Use control path for ACK of FIN
		HandleSegment(a, ackB)
	}
	if a.State != StateFinWait2 {
		t.Fatalf("A should be FIN-WAIT-2 after ACK, got %v", a.State)
	}
	// B passive close -> LAST-ACK, FIN Seq 2001
	finB, _ := Close(b, qb)
	if b.State != StateLastAck || finB.SeqNum != 2001 {
		t.Fatalf("B Close LAST-ACK %v %+v", b.State, finB)
	}
	// A receives FIN from B (2001) in FIN-WAIT-2 -> TIME-WAIT, RcvNxt 2002
	delivered, ackA2, _ := Recv(a, qa, finB, nil)
	if a.State != StateTimeWait {
		t.Fatalf("A after peer FIN state %v want TIME-WAIT", a.State)
	}
	if a.RcvNxt != 2002 {
		t.Errorf("A RcvNxt %d want 2002", a.RcvNxt)
	}
	if ackA2.AckNum != 2002 {
		t.Errorf("A final ack %d want 2002", ackA2.AckNum)
	}
	if len(delivered) != 0 {
		t.Errorf("FIN no payload")
	}
	// B receives ACK of its FIN (from A's fin ack)
	HandleSegment(b, ackA2)
	if b.State != StateClosed {
		t.Fatalf("B should be CLOSED after LAST-ACK ack, got %v", b.State)
	}
	// A TIME-WAIT expiry
	if !a.TimeWaitUntil.After(time.Now()) {
		t.Error("TIME-WAIT deadline not set")
	}
	// Fast-forward 2MSL
	future := a.TimeWaitUntil.Add(time.Nanosecond)
	if !a.TimeWaitExpired(future) {
		t.Error("should be expired")
	}
	if !a.CloseTimeWait(future) || a.State != StateClosed {
		t.Errorf("A should transition to CLOSED after 2MSL, state %v", a.State)
	}
}

func TestSimultaneousClose(t *testing.T) {
	local := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("10.0.0.2")
	a := establishedForClose()
	a.LocalAddr = local
	a.RemoteAddr = remote
	b := establishedForClose()
	b.LocalAddr = remote
	b.RemoteAddr = local
	b.LocalPort = 80
	b.RemotePort = 12345
	// Both ESTABLISHED with same base
	a.SndUna = 1001
	a.SndNxt = 1001
	a.RcvNxt = 2001
	b.SndUna = 2001
	b.SndNxt = 2001
	b.RcvNxt = 1001
	qa := retransmit.NewQueue(nil)
	qb := retransmit.NewQueue(nil)
	finA, _ := Close(a, qa) // A FIN-WAIT-1 Seq 1001
	finB, _ := Close(b, qb) // B FIN-WAIT-1 Seq 2001
	// Both receive peer FIN while in FIN-WAIT-1 -> CLOSING
	// Use HandleSegment for simultaneous (both FIN without ack of peer FIN yet? FIN Seq peer, Ack maybe not covering)
	// For simplicity let finA arrive at B (B is FIN-WAIT-1, receives FIN 1001)
	_, _ = HandleSegment(b, finA)
	if b.State != StateClosing {
		t.Fatalf("B simultaneous FIN state %v want CLOSING", b.State)
	}
	_, _ = HandleSegment(a, finB)
	if a.State != StateClosing {
		t.Fatalf("A simultaneous state %v want CLOSING", a.State)
	}
	// Now both receive ACK of their FIN: ack of 1002 and 2002 via HandleSegment
	ackA := &Header{SrcPort: 80, DstPort: 12345, SeqNum: 2002, AckNum: 1002, Flags: FlagACK, Window: 4096}
	ackB := &Header{SrcPort: 12345, DstPort: 80, SeqNum: 1002, AckNum: 2002, Flags: FlagACK, Window: 4096}
	HandleSegment(a, ackA)
	HandleSegment(b, ackB)
	if a.State != StateTimeWait || b.State != StateTimeWait {
		t.Errorf("both should be TIME-WAIT got A %v B %v", a.State, b.State)
	}
}

func TestTimeWaitRestartAndTimeout(t *testing.T) {
	tcb := establishedForClose()
	now := time.Unix(0, 0)
	tcb.EnterTimeWait(now, 10*time.Second)
	if !tcb.TimeWaitExpired(now.Add(11 * time.Second)) {
		t.Error("should be expired after 11s")
	}
	if tcb.TimeWaitExpired(now.Add(9 * time.Second)) {
		t.Error("should not be expired at 9s")
	}
	// Restart
	tcb.EnterTimeWait(now.Add(5*time.Second), 10*time.Second)
	if tcb.TimeWaitUntil != now.Add(15*time.Second) {
		t.Errorf("restart deadline %v want %v", tcb.TimeWaitUntil, now.Add(15*time.Second))
	}
	// Timeout via helper
	if !TimeWaitTimeout(tcb, now.Add(16*time.Second)) {
		t.Error("TimeWaitTimeout should close")
	}
	if tcb.State != StateClosed {
		t.Error("should be CLOSED")
	}
}

func TestHandleSegmentFINTransitions(t *testing.T) {
	tcb := establishedForClose()
	// ESTABLISHED recv FIN -> CLOSE-WAIT
	fin := &Header{SrcPort: 80, DstPort: 12345, SeqNum: 2001, AckNum: 1001, Flags: FlagFIN | FlagACK, Window: 4096}
	ack, err := HandleSegment(tcb, fin)
	if err != nil {
		t.Fatalf("HandleSegment FIN: %v", err)
	}
	if tcb.State != StateCloseWait || tcb.RcvNxt != 2002 {
		t.Errorf("ESTABLISHED FIN state %v RcvNxt %d", tcb.State, tcb.RcvNxt)
	}
	if ack == nil || ack.AckNum != 2002 {
		t.Errorf("ack %+v", ack)
	}
	// FIN-WAIT-1 recv ACK -> FIN-WAIT-2
	tcb2 := establishedForClose()
	tcb2.State = StateFinWait1
	tcb2.SndUna = 1001
	tcb2.SndNxt = 1002
	ackHdr := &Header{SrcPort: 80, DstPort: 12345, SeqNum: 2001, AckNum: 1002, Flags: FlagACK, Window: 4096}
	HandleSegment(tcb2, ackHdr)
	if tcb2.State != StateFinWait2 {
		t.Errorf("FIN-WAIT-1 ack -> %v want FIN-WAIT-2", tcb2.State)
	}
}

func TestRSTAbortsFromEstablished(t *testing.T) {
	tcb := establishedForClose()
	hdr := &Header{SrcPort: 80, DstPort: 12345, SeqNum: 2001, Flags: FlagRST, Window: 0}
	_, err := HandleSegment(tcb, hdr)
	if err != ErrConnectionReset || tcb.State != StateClosed {
		t.Errorf("RST should reset %v err %v", tcb.State, err)
	}
}
