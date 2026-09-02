// Package retransmit implements RTO and retransmission queue per RFC 793 §3.7
// and RFC 6298. The estimator is deterministic and does not depend on wall
// clock sleeps; callers drive it with measured RTTs and manual tick calls
// so tests remain deterministic (AGENTS.md Testing).
package retransmit

import "time"

// RFC 6298 §2 defaults (RFC 793 used simpler 1-2s initial RTO).
const (
	DefaultInitialRTO = 1 * time.Second
	DefaultMinRTO     = 200 * time.Millisecond
	DefaultMaxRTO     = 60 * time.Second
	ClockGranularity  = 1 * time.Millisecond
)

// RTO estimates retransmission timeout per RFC 6298 §2 / RFC 793 p.41.
//
// RFC 793 p.41 originally used a simple smoothed RTT; RFC 6298 refines it
// with RTTVAR. We implement the RFC 6298 algorithm because it is widely
// deployed and backward compatible, but keep the API small for the MVP.
type RTO struct {
	SRTT    time.Duration // smoothed RTT
	RTTVAR  time.Duration // RTT variation
	RTO     time.Duration // current timeout
	MinRTO  time.Duration
	MaxRTO  time.Duration
	initialized bool
}

// NewRTO returns an estimator with the given initial RTO (or DefaultInitialRTO if 0).
func NewRTO(initial time.Duration) *RTO {
	if initial == 0 {
		initial = DefaultInitialRTO
	}
	return &RTO{
		RTO:    initial,
		MinRTO: DefaultMinRTO,
		MaxRTO: DefaultMaxRTO,
	}
}

// Update incorporates a new RTT measurement (RFC 6298 §2.3).
// First measurement: SRTT←R, RTTVAR←R/2, RTO←SRTT+max(G,RTTVAR*4)
// Subsequent: RTTVAR←(1-β)RTTVAR+β|SRTT-R|, SRTT←(1-α)SRTT+αR, RTO←SRTT+max(G,RTTVAR*4)
func (r *RTO) Update(rtt time.Duration) {
	const alpha = 1.0 / 8.0
	const beta = 1.0 / 4.0
	if !r.initialized {
		r.SRTT = rtt
		r.RTTVAR = rtt / 2
		r.RTO = r.SRTT + maxDuration(ClockGranularity, r.RTTVAR*4)
		r.initialized = true
	} else {
		diff := r.SRTT - rtt
		if diff < 0 {
			diff = -diff
		}
		r.RTTVAR = time.Duration(float64(r.RTTVAR)*(1-beta) + float64(diff)*beta)
		r.SRTT = time.Duration(float64(r.SRTT)*(1-alpha) + float64(rtt)*alpha)
		r.RTO = r.SRTT + maxDuration(ClockGranularity, r.RTTVAR*4)
	}
	r.RTO = clamp(r.RTO, r.MinRTO, r.MaxRTO)
}

// Backoff doubles RTO on retransmission per RFC 6298 §2.5 exponential backoff
// (RFC 793 p.42: "exponential back-off"). Clamped to MaxRTO.
func (r *RTO) Backoff() {
	r.RTO *= 2
	if r.RTO > r.MaxRTO {
		r.RTO = r.MaxRTO
	}
}

// Timeout returns the current RTO.
func (r *RTO) Timeout() time.Duration { return r.RTO }

func clamp(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
