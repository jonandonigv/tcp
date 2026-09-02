package tcp

import "testing"

func TestStateString(t *testing.T) {
	tests := []struct {
		s    State
		want string
	}{
		{StateClosed, "CLOSED"},
		{StateListen, "LISTEN"},
		{StateSynSent, "SYN-SENT"},
		{StateSynReceived, "SYN-RECEIVED"},
		{StateEstablished, "ESTABLISHED"},
		{StateFinWait1, "FIN-WAIT-1"},
		{StateFinWait2, "FIN-WAIT-2"},
		{StateCloseWait, "CLOSE-WAIT"},
		{StateClosing, "CLOSING"},
		{StateLastAck, "LAST-ACK"},
		{StateTimeWait, "TIME-WAIT"},
	}
	for _, tc := range tests {
		if got := tc.s.String(); got != tc.want {
			t.Errorf("State %d String=%q want %q", tc.s, got, tc.want)
		}
	}
	if got := State(99).String(); got != "State(99)" {
		t.Errorf("unknown state string %q", got)
	}
}

func TestCanTransitionTo(t *testing.T) {
	// Valid edges per RFC 793 Figure 6
	valid := []struct{ from, to State }{
		{StateClosed, StateListen},
		{StateClosed, StateSynSent},
		{StateListen, StateSynReceived},
		{StateListen, StateSynSent},
		{StateListen, StateClosed},
		{StateSynSent, StateEstablished},
		{StateSynReceived, StateEstablished},
		{StateEstablished, StateFinWait1},
		{StateEstablished, StateCloseWait},
		{StateFinWait1, StateFinWait2},
		{StateFinWait1, StateClosing},
		{StateFinWait1, StateTimeWait},
		{StateFinWait2, StateTimeWait},
		{StateCloseWait, StateLastAck},
		{StateClosing, StateTimeWait},
		{StateLastAck, StateClosed},
		{StateTimeWait, StateClosed},
	}
	for _, tc := range valid {
		if !tc.from.CanTransitionTo(tc.to) {
			t.Errorf("CanTransitionTo %v→%v want true", tc.from, tc.to)
		}
	}
	invalid := []struct{ from, to State }{
		{StateClosed, StateEstablished},
		{StateListen, StateEstablished},
		{StateEstablished, StateSynSent},
		{StateTimeWait, StateEstablished},
		{StateFinWait2, StateFinWait1},
	}
	for _, tc := range invalid {
		if tc.from.CanTransitionTo(tc.to) {
			t.Errorf("CanTransitionTo %v→%v want false", tc.from, tc.to)
		}
	}
}

func TestNextStatePassiveOpenHandshake(t *testing.T) {
	// Passive open: CLOSED --PASSIVE_OPEN--> LISTEN --RCV_SYN--> SYN_RECEIVED --RCV_ACK--> ESTABLISHED
	s := StateClosed
	var err error
	s, err = NextState(s, EventPassiveOpen)
	if err != nil || s != StateListen {
		t.Fatalf("CLOSED passive open got %v err %v want LISTEN", s, err)
	}
	s, err = NextState(s, EventRcvSyn)
	if err != nil || s != StateSynReceived {
		t.Fatalf("LISTEN RCV_SYN got %v err %v want SYN-RECEIVED", s, err)
	}
	s, err = NextState(s, EventRcvAck)
	if err != nil || s != StateEstablished {
		t.Fatalf("SYN-RECEIVED RCV_ACK got %v err %v want ESTABLISHED", s, err)
	}
	// ESTABLISHED --RCV_FIN--> CLOSE_WAIT --CLOSE--> LAST_ACK --RCV_ACK--> CLOSED
	s, err = NextState(s, EventRcvFin)
	if err != nil || s != StateCloseWait {
		t.Fatalf("ESTABLISHED RCV_FIN got %v", s)
	}
	s, err = NextState(s, EventClose)
	if err != nil || s != StateLastAck {
		t.Fatalf("CLOSE_WAIT CLOSE got %v", s)
	}
	s, err = NextState(s, EventRcvAck)
	if err != nil || s != StateClosed {
		t.Fatalf("LAST_ACK RCV_ACK got %v", s)
	}
}

func TestNextStateActiveOpenHandshake(t *testing.T) {
	// Active open: CLOSED --ACTIVE_OPEN--> SYN_SENT --RCV_SYNACK--> ESTABLISHED --CLOSE--> FIN_WAIT1 --RCV_ACK--> FIN_WAIT2 --RCV_FIN--> TIME_WAIT --TIMEWAIT--> CLOSED
	s := StateClosed
	s, _ = NextState(s, EventActiveOpen)
	if s != StateSynSent {
		t.Fatalf("want SYN_SENT got %v", s)
	}
	s, _ = NextState(s, EventRcvSynAck)
	if s != StateEstablished {
		t.Fatalf("want ESTABLISHED got %v", s)
	}
	s, _ = NextState(s, EventClose)
	if s != StateFinWait1 {
		t.Fatalf("want FIN_WAIT1 got %v", s)
	}
	s, _ = NextState(s, EventRcvAck)
	if s != StateFinWait2 {
		t.Fatalf("want FIN_WAIT2 got %v", s)
	}
	s, _ = NextState(s, EventRcvFin)
	if s != StateTimeWait {
		t.Fatalf("want TIME_WAIT got %v", s)
	}
	s, _ = NextState(s, EventTimeWaitTimeout)
	if s != StateClosed {
		t.Fatalf("want CLOSED got %v", s)
	}
}

func TestNextStateSimultaneousClose(t *testing.T) {
	// ESTABLISHED -> FIN_WAIT1 --RCV_FIN--> CLOSING --RCV_ACK--> TIME_WAIT
	s := StateEstablished
	s, _ = NextState(s, EventClose)
	if s != StateFinWait1 {
		t.Fatalf("ESTABLISHED CLOSE want FIN_WAIT1 got %v", s)
	}
	s, _ = NextState(s, EventRcvFin)
	if s != StateClosing {
		t.Fatalf("FIN_WAIT1 RCV_FIN want CLOSING got %v", s)
	}
	s, _ = NextState(s, EventRcvAck)
	if s != StateTimeWait {
		t.Fatalf("CLOSING RCV_ACK want TIME_WAIT got %v", s)
	}
}

func TestNextStateInvalid(t *testing.T) {
	// Illegal event in CLOSED
	if _, err := NextState(StateClosed, EventRcvFin); err == nil {
		t.Error("want error for CLOSED RCV_FIN")
	}
	// Invalid state
	if _, err := NextState(State(99), EventPassiveOpen); err == nil {
		t.Error("want error for invalid state")
	}
	// SEND/RECEIVE no-op in ESTABLISHED
	s, err := NextState(StateEstablished, EventSend)
	if err != nil || s != StateEstablished {
		t.Errorf("SEND in ESTABLISHED should be no-op got %v err %v", s, err)
	}
	s, err = NextState(StateClosed, EventSend)
	if err == nil {
		t.Errorf("SEND in CLOSED should be illegal got %v", s)
	}
}

func TestIsSynchronized(t *testing.T) {
	if StateClosed.IsSynchronized() || StateListen.IsSynchronized() || StateSynSent.IsSynchronized() || StateSynReceived.IsSynchronized() {
		t.Error("pre-sync states should not be synchronized")
	}
	syncStates := []State{StateEstablished, StateFinWait1, StateFinWait2, StateCloseWait, StateClosing, StateLastAck, StateTimeWait}
	for _, s := range syncStates {
		if !s.IsSynchronized() {
			t.Errorf("%v should be synchronized", s)
		}
	}
}

func TestEventString(t *testing.T) {
	if EventPassiveOpen.String() != "PASSIVE_OPEN" {
		t.Error("event string mismatch")
	}
	if Event(99).String() != "Event(99)" {
		t.Error("unknown event string")
	}
}
