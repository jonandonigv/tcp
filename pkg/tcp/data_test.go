package tcp

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/jonandonigv/tcp/pkg/retransmit"
)

func establishedTCB() *TCB {
	local := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("10.0.0.2")
	tcb, _ := NewTCB(local, 12345, remote, 80, StateEstablished, 1000, 4096)
	tcb.ISS = 1000
	tcb.SndUna = 1001 // SYN acked
	tcb.SndNxt = 1001
	tcb.SndWnd = 4096
	tcb.IRS = 2000
	tcb.RcvNxt = 2001
	tcb.RcvWnd = 8192
	if tcb.Reassembly == nil {
		tcb.Reassembly = make(map[uint32][]byte)
	}
	return tcb
}

func TestSendMSSChunkingAndWindow(t *testing.T) {
	tcb := establishedTCB()
	q := retransmit.NewQueue(nil)
	data := bytes.Repeat([]byte("A"), 3000)
	mss := 1000
	hdrs, err := Send(tcb, q, data, mss)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(hdrs) != 3 {
		t.Fatalf("hdrs %d want 3", len(hdrs))
	}
	if tcb.SndNxt != 4001 { // 1001+3000
		t.Errorf("SndNxt %d want 4001", tcb.SndNxt)
	}
	if q.Len() != 3 {
		t.Errorf("queue len %d want 3", q.Len())
	}
	// Verify seq progression
	if hdrs[0].SeqNum != 1001 || hdrs[1].SeqNum != 2001 || hdrs[2].SeqNum != 3001 {
		t.Errorf("seqs %d %d %d", hdrs[0].SeqNum, hdrs[1].SeqNum, hdrs[2].SeqNum)
	}
	for _, h := range hdrs {
		if !h.HasFlag(FlagPSH|FlagACK) {
			t.Errorf("flags %06b want PSH|ACK", h.Flags)
		}
	}
}

func TestSendRespectsWindow(t *testing.T) {
	tcb := establishedTCB()
	tcb.SndWnd = 1500
	tcb.SndUna = 1001
	tcb.SndNxt = 1001
	q := retransmit.NewQueue(nil)
	data := bytes.Repeat([]byte("B"), 3000)
	hdrs, err := Send(tcb, q, data, 1000)
	if err != nil {
		t.Fatalf("Send window: %v", err)
	}
	// usable = 1500, so only 1500 bytes -> 2 segments (1000+500)
	if len(hdrs) != 2 {
		t.Fatalf("hdrs %d want 2 (window limited)", len(hdrs))
	}
	if tcb.SndNxt != 2501 {
		t.Errorf("SndNxt %d want 2501", tcb.SndNxt)
	}
	// Next send should hit zero window (outstanding 1500 == WND)
	_, err = Send(tcb, q, []byte("x"), 0)
	if err != ErrZeroWindow {
		t.Errorf("want ErrZeroWindow got %v", err)
	}
}

func TestSendZeroWindow(t *testing.T) {
	tcb := establishedTCB()
	tcb.SndWnd = 0
	q := retransmit.NewQueue(nil)
	if _, err := Send(tcb, q, []byte("hi"), 0); err != ErrZeroWindow {
		t.Errorf("zero window err %v want ErrZeroWindow", err)
	}
}

func TestRecvInOrder(t *testing.T) {
	tcb := establishedTCB()
	q := retransmit.NewQueue(nil)
	payload := []byte("hello")
	hdr := &Header{SrcPort: 80, DstPort: 12345, SeqNum: 2001, AckNum: 1001, Flags: FlagACK, Window: 4096}
	delivered, ack, err := Recv(tcb, q, hdr, payload)
	if err != nil {
		t.Fatalf("Recv err %v", err)
	}
	if string(delivered) != "hello" {
		t.Errorf("delivered %q want hello", delivered)
	}
	if tcb.RcvNxt != 2006 {
		t.Errorf("RcvNxt %d want 2006", tcb.RcvNxt)
	}
	if ack == nil || ack.AckNum != 2006 || ack.SeqNum != tcb.SndNxt {
		t.Errorf("ack %+v", ack)
	}
}

func TestRecvOutOfOrderBuffering(t *testing.T) {
	tcb := establishedTCB()
	q := retransmit.NewQueue(nil)
	// Send seq 2001-2005 and 2006-2010 but out of order: second arrives first
	hdr1 := &Header{SrcPort: 80, DstPort: 12345, SeqNum: 2006, AckNum: 1001, Flags: FlagACK, Window: 4096}
	payload1 := []byte("world")
	delivered, ack, err := Recv(tcb, q, hdr1, payload1)
	if err != nil {
		t.Fatalf("ooo first err %v", err)
	}
	if len(delivered) != 0 {
		t.Errorf("ooo should buffer not deliver %q", delivered)
	}
	if len(tcb.Reassembly) != 1 {
		t.Error("should have 1 buffered")
	}
	if ack.AckNum != 2001 {
		t.Errorf("ack should still be 2001 got %d", ack.AckNum)
	}
	// Now in-order arrives and should reassemble both
	hdr2 := &Header{SrcPort: 80, DstPort: 12345, SeqNum: 2001, AckNum: 1001, Flags: FlagACK, Window: 4096}
	payload2 := []byte("hello")
	delivered, ack, err = Recv(tcb, q, hdr2, payload2)
	if err != nil {
		t.Fatalf("in-order err %v", err)
	}
	if string(delivered) != "helloworld" {
		t.Errorf("reassembled %q want helloworld", delivered)
	}
	if tcb.RcvNxt != 2011 {
		t.Errorf("RcvNxt %d want 2011", tcb.RcvNxt)
	}
	if len(tcb.Reassembly) != 0 {
		t.Error("reassembly should be drained")
	}
	if ack.AckNum != 2011 {
		t.Errorf("ack %d want 2011", ack.AckNum)
	}
}

func TestRecvDuplicate(t *testing.T) {
	tcb := establishedTCB()
	q := retransmit.NewQueue(nil)
	hdr := &Header{SrcPort: 80, DstPort: 12345, SeqNum: 2001, AckNum: 1001, Flags: FlagACK, Window: 4096}
	Recv(tcb, q, hdr, []byte("hello"))
	// Duplicate same seq (already acked) -> should duplicate ack, no deliver
	hdr2 := &Header{SrcPort: 80, DstPort: 12345, SeqNum: 2001, AckNum: 1001, Flags: FlagACK, Window: 4096}
	delivered, ack, _ := Recv(tcb, q, hdr2, []byte("hello"))
	if len(delivered) != 0 {
		t.Errorf("duplicate should not deliver")
	}
	if ack.AckNum != 2006 { // RcvNxt still 2006 after first
		t.Errorf("dup ack %d want 2006", ack.AckNum)
	}
}

func TestRecvOutOfWindow(t *testing.T) {
	tcb := establishedTCB()
	tcb.RcvWnd = 10
	tcb.RcvNxt = 1000
	q := retransmit.NewQueue(nil)
	// Payload seq 2000 far outside window [1000,1010)
	hdr := &Header{SrcPort: 80, DstPort: 12345, SeqNum: 2000, AckNum: 1001, Flags: FlagACK, Window: 4096}
	_, ack, err := Recv(tcb, q, hdr, []byte("x"))
	if err != ErrSegmentOutOfWindow {
		t.Errorf("want ErrSegmentOutOfWindow got %v", err)
	}
	if ack == nil || ack.AckNum != 1000 {
		t.Errorf("out-of-window should ack RCV.NXT 1000 got %v", ack)
	}
	if tcb.RcvNxt != 1000 {
		t.Error("RcvNxt should not advance")
	}
}

func TestRecvAckProcessingAndWindowUpdate(t *testing.T) {
	tcb := establishedTCB()
	tcb.SndUna = 1001
	tcb.SndNxt = 1101 // 100 outstanding
	tcb.SndWnd = 1000
	tcb.SndWL1 = 2000
	tcb.SndWL2 = 1000
	q := retransmit.NewQueue(nil)
	q.Enqueue(1001, bytes.Repeat([]byte("x"), 100))
	// Incoming ACK 1101 advances UNA, updates window via WL check (Seq==WL1? No, Seq 2001 > WL1 2000 -> update)
	hdr := &Header{SrcPort: 80, DstPort: 12345, SeqNum: 2001, AckNum: 1101, Flags: FlagACK, Window: 2048}
	delivered, ack, err := Recv(tcb, q, hdr, nil)
	if err != nil {
		t.Fatalf("Recv ack err %v", err)
	}
	if tcb.SndUna != 1101 {
		t.Errorf("SndUna %d want 1101", tcb.SndUna)
	}
	if q.Len() != 0 {
		t.Errorf("queue should be acked len %d", q.Len())
	}
	if tcb.SndWnd != 2048 {
		t.Errorf("SndWnd %d want 2048", tcb.SndWnd)
	}
	if delivered != nil || ack != nil {
		// pure ACK no data -> no ack generated
		if ack != nil {
			t.Errorf("pure ACK should not generate ack")
		}
	}
}

func TestRecvAckNotAcceptableDropped(t *testing.T) {
	tcb := establishedTCB()
	tcb.SndUna = 1001
	tcb.SndNxt = 1101
	q := retransmit.NewQueue(nil)
	hdr := &Header{SrcPort: 80, DstPort: 12345, SeqNum: 2001, AckNum: 9999, Flags: FlagACK, Window: 4096}
	_, ack, err := Recv(tcb, q, hdr, []byte("data"))
	if err != ErrAckNotAcceptable {
		t.Errorf("want ErrAckNotAcceptable got %v", err)
	}
	if ack == nil {
		t.Error("should return duplicate ack even on bad ack")
	}
}

func TestIsSegmentAcceptable(t *testing.T) {
	tcb := establishedTCB()
	tcb.RcvNxt = 1000
	tcb.RcvWnd = 100
	tests := []struct {
		seq  uint32
		len  int
		want bool
	}{
		{1000, 0, true},  // zero-len at RCV.NXT
		{999, 0, false},  // zero-len off
		{1000, 10, true}, // in window
		{1095, 10, true}, // overlap at end
		{1100, 1, false}, // just beyond
		{900, 50, false}, // before window
	}
	for _, tc := range tests {
		h := &Header{SeqNum: tc.seq}
		if got := IsSegmentAcceptable(tcb, h, tc.len); got != tc.want {
			t.Errorf("Acceptable seq %d len %d got %v want %v", tc.seq, tc.len, got, tc.want)
		}
	}
	// SYN flag adds 1 to len
	h := &Header{SeqNum: 1000, Flags: FlagSYN}
	if !IsSegmentAcceptable(tcb, h, 0) {
		t.Error("SYN segment should be acceptable")
	}
}
