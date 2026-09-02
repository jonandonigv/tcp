package tcp

import (
	"net/netip"
	"testing"
)

func TestActiveOpen(t *testing.T) {
	local := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("10.0.0.2")
	tcb, syn, err := ActiveOpen(local, 12345, remote, 80, 1000, 4096)
	if err != nil {
		t.Fatalf("ActiveOpen: %v", err)
	}
	if tcb.State != StateSynSent {
		t.Errorf("state %v want SYN-SENT", tcb.State)
	}
	if tcb.SndNxt != 1001 || tcb.SndUna != 1000 {
		t.Errorf("SND.NXT/UNA %d/%d want 1001/1000", tcb.SndNxt, tcb.SndUna)
	}
	if syn.SeqNum != 1000 || !syn.HasFlag(FlagSYN) || syn.HasFlag(FlagACK) {
		t.Errorf("SYN hdr %+v", syn)
	}
	if syn.Window != 4096 {
		t.Errorf("Window %d want 4096", syn.Window)
	}
}

func TestPassiveOpenHandshake(t *testing.T) {
	local := netip.MustParseAddr("10.0.0.1")
	peer := netip.MustParseAddr("10.0.0.2")
	listen, err := PassiveOpen(local, 80, 8192)
	if err != nil {
		t.Fatalf("PassiveOpen: %v", err)
	}
	if listen.State != StateListen {
		t.Fatalf("listen state %v", listen.State)
	}
	// Peer SYN
	syn := &Header{SrcPort: 12345, DstPort: 80, SeqNum: 5000, Flags: FlagSYN, Window: 65535}
	child, synAck, err := HandleListenSegmentWithAddrs(listen, syn, peer, 1000)
	if err != nil {
		t.Fatalf("HandleListenSegment: %v", err)
	}
	if child == nil || synAck == nil {
		t.Fatal("want child and SYN-ACK")
	}
	if child.State != StateSynReceived {
		t.Errorf("child state %v want SYN-RECEIVED", child.State)
	}
	if child.IRS != 5000 || child.RcvNxt != 5001 {
		t.Errorf("IRS/RcvNxt %d/%d want 5000/5001", child.IRS, child.RcvNxt)
	}
	if child.ISS != 1000 || child.SndNxt != 1001 {
		t.Errorf("ISS/SndNxt %d/%d want 1000/1001", child.ISS, child.SndNxt)
	}
	if synAck.SeqNum != 1000 || synAck.AckNum != 5001 || synAck.Flags != FlagSYN|FlagACK {
		t.Errorf("SYN-ACK %+v", synAck)
	}
	// Listen still LISTEN
	if listen.State != StateListen {
		t.Errorf("listen mutated to %v", listen.State)
	}
	// Child receives ACK of its SYN => ESTABLISHED (RFC 793 p.36)
	ack := &Header{SrcPort: 12345, DstPort: 80, SeqNum: 5001, AckNum: 1001, Flags: FlagACK, Window: 4096}
	reply, err := HandleSegment(child, ack)
	if err != nil {
		t.Fatalf("HandleSegment ACK: %v", err)
	}
	if reply != nil {
		t.Errorf("ACK should consume with no reply got %+v", reply)
	}
	if child.State != StateEstablished {
		t.Errorf("child state after ACK %v want ESTABLISHED", child.State)
	}
	if child.SndUna != 1001 {
		t.Errorf("SndUna %d want 1001", child.SndUna)
	}
}

func TestActiveOpenHandshake(t *testing.T) {
	local := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("10.0.0.2")
	tcb, _, _ := ActiveOpen(local, 12345, remote, 80, 7000, 4096)
	// Peer SYN-ACK: Seq=9000 Ack=7001 (acks our SYN)
	synAck := &Header{SrcPort: 80, DstPort: 12345, SeqNum: 9000, AckNum: 7001, Flags: FlagSYN | FlagACK, Window: 8192}
	reply, err := HandleSegment(tcb, synAck)
	if err != nil {
		t.Fatalf("HandleSegment SYN-ACK: %v", err)
	}
	if tcb.State != StateEstablished {
		t.Errorf("state %v want ESTABLISHED", tcb.State)
	}
	if tcb.IRS != 9000 || tcb.RcvNxt != 9001 {
		t.Errorf("IRS/RcvNxt %d/%d want 9000/9001", tcb.IRS, tcb.RcvNxt)
	}
	if tcb.SndUna != 7001 {
		t.Errorf("SndUna %d want 7001", tcb.SndUna)
	}
	if reply == nil || !reply.HasFlag(FlagACK) || reply.SeqNum != 7001 || reply.AckNum != 9001 {
		t.Fatalf("reply ACK %+v want Seq 7001 Ack 9001 ACK flag", reply)
	}
	// Now data path quiescent: further ACK no-op
	ack2 := &Header{SrcPort: 80, DstPort: 12345, SeqNum: 9001, AckNum: 7001, Flags: FlagACK, Window: 8192}
	if reply2, err := HandleSegment(tcb, ack2); err != nil || reply2 != nil {
		t.Errorf("ESTABLISHED ACK should be no-op err %v reply %v", err, reply2)
	}
}

func TestSimultaneousOpen(t *testing.T) {
	local := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("10.0.0.2")
	tcb, _, _ := ActiveOpen(local, 12345, remote, 80, 1000, 4096)
	// Peer SYN without ACK (simultaneous)
	syn := &Header{SrcPort: 80, DstPort: 12345, SeqNum: 2000, Flags: FlagSYN, Window: 4096}
	reply, err := HandleSegment(tcb, syn)
	if err != nil {
		t.Fatalf("sim SYN: %v", err)
	}
	if tcb.State != StateSynReceived {
		t.Errorf("state %v want SYN-RECEIVED", tcb.State)
	}
	if reply == nil || reply.Flags != FlagSYN|FlagACK {
		t.Errorf("reply %+v want SYN|ACK", reply)
	}
	if reply.SeqNum != 1000 || reply.AckNum != 2001 {
		t.Errorf("reply Seq/Ack %d/%d want 1000/2001", reply.SeqNum, reply.AckNum)
	}
	// Peer now sends ACK of our SYN => ESTABLISHED
	ack := &Header{SrcPort: 80, DstPort: 12345, SeqNum: 2001, AckNum: 1001, Flags: FlagACK, Window: 4096}
	if reply2, err := HandleSegment(tcb, ack); err != nil || reply2 != nil {
		t.Fatalf("SYN-RECEIVED ACK err %v reply %v", err, reply2)
	}
	if tcb.State != StateEstablished {
		t.Errorf("after ACK state %v want ESTABLISHED", tcb.State)
	}
}

func TestListenIgnoresRSTAndACK(t *testing.T) {
	local := netip.MustParseAddr("10.0.0.1")
	peer := netip.MustParseAddr("10.0.0.2")
	listen, _ := PassiveOpen(local, 80, 4096)
	// RST in LISTEN
	rst := &Header{SrcPort: 1234, DstPort: 80, Flags: FlagRST, SeqNum: 0}
	if child, reply, err := HandleListenSegmentWithAddrs(listen, rst, peer, 1000); err != nil || child != nil || reply != nil {
		t.Errorf("RST in LISTEN should be dropped child %v reply %v err %v", child, reply, err)
	}
	// ACK in LISTEN
	ack := &Header{SrcPort: 1234, DstPort: 80, Flags: FlagACK, AckNum: 1, SeqNum: 0}
	if child, reply, err := HandleListenSegmentWithAddrs(listen, ack, peer, 1000); err != nil || child != nil || reply != nil {
		t.Errorf("ACK in LISTEN should be dropped child %v reply %v err %v", child, reply, err)
	}
	// non-SYN (e.g., FIN) dropped
	fin := &Header{SrcPort: 1234, DstPort: 80, Flags: FlagFIN, SeqNum: 0}
	if child, reply, err := HandleListenSegmentWithAddrs(listen, fin, peer, 1000); err != nil || child != nil || reply != nil {
		t.Errorf("FIN in LISTEN should be dropped")
	}
}

func TestSynSentRST(t *testing.T) {
	local := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("10.0.0.2")
	tcb, _, _ := ActiveOpen(local, 12345, remote, 80, 5000, 4096)
	// RST with acceptable ACK closes
	rst := &Header{SrcPort: 80, DstPort: 12345, SeqNum: 0, AckNum: 5001, Flags: FlagRST | FlagACK, Window: 0}
	_, err := HandleSegment(tcb, rst)
	if err == nil || tcb.State != StateClosed {
		t.Errorf("acceptable RST should close SYN-SENT, state %v err %v", tcb.State, err)
	}
	// RST with unacceptable ACK dropped
	tcb2, _, _ := ActiveOpen(local, 12345, remote, 80, 5000, 4096)
	badRST := &Header{SrcPort: 80, DstPort: 12345, SeqNum: 0, AckNum: 9999, Flags: FlagRST | FlagACK}
	if reply, err := HandleSegment(tcb2, badRST); err != nil || reply != nil {
		t.Errorf("unacceptable RST ACK should be dropped err %v", err)
	}
	if tcb2.State != StateSynSent {
		t.Errorf("tcb2 state %v should remain SYN-SENT", tcb2.State)
	}
}

func TestSynReceivedRST(t *testing.T) {
	local := netip.MustParseAddr("10.0.0.1")
	peer := netip.MustParseAddr("10.0.0.2")
	listen, _ := PassiveOpen(local, 80, 4096)
	syn := &Header{SrcPort: 12345, DstPort: 80, SeqNum: 100, Flags: FlagSYN, Window: 4096}
	child, _, _ := HandleListenSegmentWithAddrs(listen, syn, peer, 2000)
	rst := &Header{SrcPort: 12345, DstPort: 80, SeqNum: 101, Flags: FlagRST, Window: 0}
	_, err := HandleSegment(child, rst)
	if err == nil || child.State != StateClosed {
		t.Errorf("RST in SYN-RECEIVED should close, state %v err %v", child.State, err)
	}
}

func TestSynSentAckNotAcceptable(t *testing.T) {
	local := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("10.0.0.2")
	tcb, _, _ := ActiveOpen(local, 12345, remote, 80, 1000, 4096)
	// SYN-ACK with bad ack (not acking SYN)
	bad := &Header{SrcPort: 80, DstPort: 12345, SeqNum: 2000, AckNum: 9999, Flags: FlagSYN | FlagACK, Window: 0}
	if _, err := HandleSegment(tcb, bad); err == nil {
		t.Error("bad ack should error")
	}
	if tcb.State != StateSynSent {
		t.Error("state should remain SYN-SENT on bad ack")
	}
}

func TestHandleSegmentOnListenErrors(t *testing.T) {
	local := netip.MustParseAddr("10.0.0.1")
	listen, _ := PassiveOpen(local, 80, 4096)
	seg := &Header{SrcPort: 1, DstPort: 80, Flags: FlagSYN, SeqNum: 1}
	if _, err := HandleSegment(listen, seg); err == nil {
		t.Error("HandleSegment on LISTEN should error")
	}
}

func TestFullPassiveAndActiveHandshakeWithBytes(t *testing.T) {
	// End-to-end handshake using marshaled headers (checksum ignored for handshake)
	local := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("10.0.0.2")
	// Active side
	active, synHdr, _ := ActiveOpen(local, 12345, remote, 80, 1111, 4096)
	// Passive side
	listen, _ := PassiveOpen(remote, 80, 8192)
	// Passive receives SYN
	child, synAckHdr, _ := HandleListenSegmentWithAddrs(listen, synHdr, local, 2222)
	// Active receives SYN-ACK
	ackHdr, err := HandleSegment(active, synAckHdr)
	if err != nil {
		t.Fatalf("active SYN-ACK: %v", err)
	}
	if active.State != StateEstablished || child.State != StateSynReceived {
		t.Fatalf("states active %v child %v", active.State, child.State)
	}
	// Passive child receives ACK
	if _, err := HandleSegment(child, ackHdr); err != nil {
		t.Fatalf("child ACK: %v", err)
	}
	if child.State != StateEstablished {
		t.Errorf("child should be ESTABLISHED after final ACK")
	}
	// Verify seq/ack coherence: active SND.NXT == ackHdr.SeqNum, active RCV.NXT == ackHdr.AckNum == child SND.NXT
	if ackHdr.SeqNum != active.SndNxt {
		t.Errorf("ACK Seq %d vs active SND.NXT %d", ackHdr.SeqNum, active.SndNxt)
	}
	if ackHdr.AckNum != active.RcvNxt {
		t.Errorf("ACK Ack %d vs active RcvNxt %d", ackHdr.AckNum, active.RcvNxt)
	}
	if ackHdr.AckNum != child.SndNxt {
		t.Errorf("ACK Ack %d vs child SND.NXT %d", ackHdr.AckNum, child.SndNxt)
	}
}

func TestBuildAck(t *testing.T) {
	local := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("10.0.0.2")
	tcb, _ := NewTCB(local, 1, remote, 2, StateEstablished, 1000, 4096)
	tcb.SndNxt = 1500
	tcb.RcvNxt = 2000
	h := BuildAck(tcb)
	if h.SeqNum != 1500 || h.AckNum != 2000 || h.Flags != FlagACK {
		t.Errorf("BuildAck %+v", h)
	}
}
