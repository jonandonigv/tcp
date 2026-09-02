package tcp

import (
	"net/netip"
	"testing"
)

func TestNewTCBInit(t *testing.T) {
	local := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("10.0.0.2")
	tcb, err := NewTCB(local, 12345, remote, 80, StateEstablished, 1000, 4096)
	if err != nil {
		t.Fatalf("NewTCB: %v", err)
	}
	if tcb.ISS != 1000 || tcb.SndUna != 1000 {
		t.Errorf("SND.UNA %d want 1000", tcb.SndUna)
	}
	if tcb.RcvWnd != 4096 {
		t.Errorf("RcvWnd %d want 4096", tcb.RcvWnd)
	}
	if tcb.State != StateEstablished {
		t.Errorf("state %v want ESTABLISHED", tcb.State)
	}
	// Default window when 0
	tcb2, _ := NewTCB(local, 12345, remote, 80, StateClosed, 0, 0)
	if tcb2.RcvWnd != DefaultRcvWindow {
		t.Errorf("default RcvWnd %d want %d", tcb2.RcvWnd, DefaultRcvWindow)
	}
	// SYN-SENT advances SND.NXT to ISS+1
	tcb3, _ := NewTCB(local, 12345, remote, 80, StateSynSent, 5000, 1024)
	if tcb3.SndNxt != 5001 {
		t.Errorf("SYN_SENT SndNxt %d want 5001", tcb3.SndNxt)
	}
	// Invalid state
	if _, err := NewTCB(local, 12345, remote, 80, State(99), 0, 0); err == nil {
		t.Error("want error for invalid state")
	}
}

func TestNewListenTCB(t *testing.T) {
	local := netip.MustParseAddr("0.0.0.0")
	tcb, err := NewListenTCB(local, 8080, 8192)
	if err != nil {
		t.Fatalf("NewListenTCB: %v", err)
	}
	if tcb.State != StateListen {
		t.Errorf("state %v want LISTEN", tcb.State)
	}
	if tcb.LocalPort != 8080 {
		t.Errorf("port %d want 8080", tcb.LocalPort)
	}
	if tcb.RemoteAddr.IsValid() {
		t.Errorf("listen remote should be invalid")
	}
}

func TestCloneForChild(t *testing.T) {
	local := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("10.0.0.2")
	listen, _ := NewListenTCB(local, 80, 4096)
	child, err := listen.CloneForChild(remote, 12345, 1000, 2000)
	if err != nil {
		t.Fatalf("CloneForChild: %v", err)
	}
	if child.State != StateSynReceived {
		t.Errorf("child state %v want SYN-RECEIVED", child.State)
	}
	if child.ISS != 1000 || child.IRS != 2000 {
		t.Errorf("ISS/IRS %d/%d want 1000/2000", child.ISS, child.IRS)
	}
	if child.RcvNxt != 2001 {
		t.Errorf("RcvNxt %d want 2001", child.RcvNxt)
	}
	if child.SndNxt != 1001 {
		t.Errorf("SndNxt %d want 1001", child.SndNxt)
	}
	// Only allowed from LISTEN
	bad, _ := NewTCB(local, 80, remote, 90, StateEstablished, 0, 0)
	if _, err := bad.CloneForChild(remote, 12345, 0, 0); err == nil {
		t.Error("CloneForChild from ESTABLISHED should fail")
	}
}

func TestInWindow(t *testing.T) {
	local := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("10.0.0.2")
	tcb, _ := NewTCB(local, 1, remote, 2, StateEstablished, 0, 0)
	tcb.RcvNxt = 1000
	tcb.RcvWnd = 100

	tests := []struct {
		seq  uint32
		want bool
	}{
		{1000, true},
		{1099, true},
		{1100, false}, // exclusive end
		{999, false},
		{1050, true},
	}
	for _, tc := range tests {
		if got := tcb.InWindow(tc.seq); got != tc.want {
			t.Errorf("InWindow(%d) got %v want %v (RcvNxt=%d Wnd=%d)", tc.seq, got, tc.want, tcb.RcvNxt, tcb.RcvWnd)
		}
	}
	// Wrap around
	tcb.RcvNxt = 0xFFFFFFF0
	tcb.RcvWnd = 32 // window [FFFFFFF0, FFFFFFF0+32) wraps to 16
	if !tcb.InWindow(0xFFFFFFF0) {
		t.Error("wrap start should be in window")
	}
	if !tcb.InWindow(0xFFFFFFFF) {
		t.Error("wrap 0xFFFFFFFF should be in window")
	}
	if !tcb.InWindow(0) {
		t.Error("wrap 0 should be in window")
	}
	if !tcb.InWindow(15) {
		t.Error("wrap 15 should be in window")
	}
	if tcb.InWindow(16) {
		t.Error("wrap 16 should be outside (exclusive end)")
	}
	if tcb.InWindow(0xFFFFFFEF) {
		t.Error("just before window should be outside")
	}
	// Zero window
	tcb.RcvNxt = 500
	tcb.RcvWnd = 0
	if !tcb.InWindow(500) {
		t.Error("zero window: only RCV.NXT exact should be true")
	}
	if tcb.InWindow(501) {
		t.Error("zero window: 501 should be false")
	}
}

func TestAckAcceptable(t *testing.T) {
	local := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("10.0.0.2")
	tcb, _ := NewTCB(local, 1, remote, 2, StateEstablished, 0, 0)
	tcb.SndUna = 1000
	tcb.SndNxt = 1100 // sent 100 bytes, UNA..NXT

	tests := []struct {
		ack  uint32
		want bool
	}{
		{1000, true},
		{1050, true},
		{1100, true}, // inclusive of NXT
		{999, false},
		{1101, false},
	}
	for _, tc := range tests {
		if got := tcb.AckAcceptable(tc.ack); got != tc.want {
			t.Errorf("AckAcceptable(%d) got %v want %v", tc.ack, got, tc.want)
		}
	}
	// Single outstanding: SND.UNA == SND.NXT means only that value is ackable
	tcb.SndUna = 500
	tcb.SndNxt = 500
	if !tcb.AckAcceptable(500) {
		t.Error("single ack should be acceptable")
	}
	if tcb.AckAcceptable(501) {
		t.Error("501 should not be acceptable when UNA==NXT==500")
	}
	// Wrapping
	tcb.SndUna = 0xFFFFFFF0
	tcb.SndNxt = 0x10 // wrapped: 0xFFFFFFF0 .. 0xFFFFFFFF, 0x00 .. 0x10
	if !tcb.AckAcceptable(0xFFFFFFF0) {
		t.Error("wrap UNA should be acceptable")
	}
	if !tcb.AckAcceptable(0) {
		t.Error("wrap 0 should be acceptable")
	}
	if !tcb.AckAcceptable(0x10) {
		t.Error("wrap NXT should be acceptable")
	}
	if tcb.AckAcceptable(0x11) {
		t.Error("wrap 0x11 should not be acceptable")
	}
}

func TestSetState(t *testing.T) {
	local := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("10.0.0.2")
	tcb, _ := NewTCB(local, 1, remote, 2, StateClosed, 0, 0)
	if err := tcb.SetState(StateListen); err != nil {
		t.Fatalf("CLOSED->LISTEN err %v", err)
	}
	if err := tcb.SetState(StateEstablished); err == nil {
		t.Error("LISTEN->ESTABLISHED should be invalid")
	}
	// Ensure state unchanged on error
	if tcb.State != StateListen {
		t.Errorf("state should remain LISTEN got %v", tcb.State)
	}
}

func TestHandleEvent(t *testing.T) {
	local := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("10.0.0.2")
	tcb, _ := NewTCB(local, 1, remote, 2, StateClosed, 123, 1024)
	// CLOSED --PASSIVE_OPEN--> LISTEN
	if err := tcb.HandleEvent(EventPassiveOpen); err != nil || tcb.State != StateListen {
		t.Fatalf("HandleEvent passive open got %v err %v", tcb.State, err)
	}
	// Prepare IRS handling: simulate SYN received
	tcb.IRS = 999
	if err := tcb.HandleEvent(EventRcvSyn); err != nil || tcb.State != StateSynReceived {
		t.Fatalf("HandleEvent RCV_SYN got %v err %v", tcb.State, err)
	}
	if tcb.RcvNxt != 1000 {
		t.Errorf("RcvNxt after RCV_SYN %d want 1000", tcb.RcvNxt)
	}
	// Illegal event should error and not change state
	prev := tcb.State
	if err := tcb.HandleEvent(EventRcvFinAck); err == nil {
		t.Error("illegal event should error")
	}
	if tcb.State != prev {
		t.Errorf("state changed on illegal event to %v", tcb.State)
	}
}

func TestTCBAdvanceAndUpdate(t *testing.T) {
	local := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("10.0.0.2")
	tcb, _ := NewTCB(local, 1, remote, 2, StateEstablished, 1000, 0)
	tcb.SndUna = 1000
	tcb.SndNxt = 1100
	tcb.RcvNxt = 5000

	tcb.AdvanceRcvNxt(100)
	if tcb.RcvNxt != 5100 {
		t.Errorf("AdvanceRcvNxt got %d want 5100", tcb.RcvNxt)
	}
	tcb.AdvanceSndNxt(50)
	if tcb.SndNxt != 1150 {
		t.Errorf("AdvanceSndNxt got %d want 1150", tcb.SndNxt)
	}
	if err := tcb.UpdateSndUna(1050); err != nil {
		t.Fatalf("UpdateSndUna 1050 err %v", err)
	}
	if tcb.SndUna != 1050 {
		t.Errorf("SndUna got %d want 1050", tcb.SndUna)
	}
	if err := tcb.UpdateSndUna(2000); err == nil {
		t.Error("UpdateSndUna out-of-window should error")
	}
}

func TestTCBString(t *testing.T) {
	local := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("10.0.0.2")
	tcb, _ := NewTCB(local, 1234, remote, 80, StateEstablished, 1, 1024)
	s := tcb.String()
	if s == "" {
		t.Error("TCB String empty")
	}
}
