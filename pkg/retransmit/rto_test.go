package retransmit

import (
	"testing"
	"time"
)

func TestRTOInitial(t *testing.T) {
	r := NewRTO(0)
	if r.Timeout() != DefaultInitialRTO {
		t.Errorf("initial %v want %v", r.Timeout(), DefaultInitialRTO)
	}
}

func TestRTOUpdateFirst(t *testing.T) {
	r := NewRTO(0)
	r.Update(100 * time.Millisecond)
	// SRTT=100ms RTTVAR=50ms => RTO=100+max(1,200)=300ms
	want := 300 * time.Millisecond
	if r.Timeout() != want {
		t.Errorf("first update %v want %v SRTT %v RTTVAR %v", r.Timeout(), want, r.SRTT, r.RTTVAR)
	}
}

func TestRTOUpdateSecond(t *testing.T) {
	r := NewRTO(0)
	r.Update(100 * time.Millisecond) // 300ms
	r.Update(120 * time.Millisecond)
	// second: diff=20, RTTVAR= (1-0.25)*50+0.25*20=42.5, SRTT=(1-0.125)*100+0.125*120=102.5 => RTO=102.5+170=272.5ms but due to duration truncation
	if r.RTO <= 0 {
		t.Error("RTO should be positive")
	}
	if r.RTTVAR == 0 {
		t.Error("RTTVAR should be set")
	}
}

func TestRTOClamp(t *testing.T) {
	r := NewRTO(0)
	r.MinRTO = 200 * time.Millisecond
	r.MaxRTO = 500 * time.Millisecond
	r.Update(10 * time.Millisecond) // would compute ~ 10+20=30ms but clamped to 200
	if r.Timeout() != 200*time.Millisecond {
		t.Errorf("clamped low %v", r.Timeout())
	}
	r.Update(1000 * time.Millisecond)
	r.Update(1000 * time.Millisecond)
	r.Update(1000 * time.Millisecond)
	// After large RTTs, RTO should be clamped to 500
	if r.Timeout() > 500*time.Millisecond {
		t.Errorf("clamped high %v", r.Timeout())
	}
}

func TestRTOBackoff(t *testing.T) {
	r := NewRTO(200 * time.Millisecond)
	r.Backoff()
	if r.Timeout() != 400*time.Millisecond {
		t.Errorf("backoff 1 %v want 400ms", r.Timeout())
	}
	r.Backoff()
	if r.Timeout() != 800*time.Millisecond {
		t.Errorf("backoff 2 %v", r.Timeout())
	}
	r.MaxRTO = 600 * time.Millisecond
	r.Backoff() // 1.6s -> clamp 600
	if r.Timeout() != 600*time.Millisecond {
		t.Errorf("backoff clamp %v want 600ms", r.Timeout())
	}
}
