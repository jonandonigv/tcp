// Package seq provides helpers for 32-bit TCP sequence number arithmetic.
//
// RFC 793 §3.3 defines sequence numbers as 32-bit unsigned values wrapping
// modulo 2^32. Comparisons must account for wrapping; a simple unsigned
// comparison is incorrect when numbers cross 2^32-1 → 0. The helpers here
// use the classic int32-difference technique: a < b iff int32(a-b) < 0.
//
// This is equivalent to the definition in RFC 793 p.20 and used by the
// Linux kernel (after / before macros). See also Stevens Vol.2 ch.24.
package seq

// LT reports whether a < b in sequence space (RFC 793 wrapping).
func LT(a, b uint32) bool {
	return int32(a-b) < 0
}

// GT reports whether a > b in sequence space.
func GT(a, b uint32) bool {
	return int32(a-b) > 0
}

// LTE reports whether a <= b in sequence space.
func LTE(a, b uint32) bool {
	return int32(a-b) <= 0
}

// GTE reports whether a >= b in sequence space.
func GTE(a, b uint32) bool {
	return int32(a-b) >= 0
}

// EQ reports whether a == b.
func EQ(a, b uint32) bool {
	return a == b
}

// Add returns a + n modulo 2^32.
func Add(a, n uint32) uint32 {
	return a + n
}

// Sub returns a - b modulo 2^32 as a uint32 distance.
func Sub(a, b uint32) uint32 {
	return a - b
}

// Between reports whether seq ∈ [start, end) in sequence space.
//
// It correctly handles wrapping intervals. If start == end the interval is
// empty and Between returns false. This corresponds to the window check
// RFC 793 §3.3 p.25: RCV.NXT <= SEG.SEQ < RCV.NXT+RCV.WND.
func Between(seq, start, end uint32) bool {
	if start == end {
		return false
	}
	// seq >= start && seq < end
	return GTE(seq, start) && LT(seq, end)
}
