package seq

import "testing"

func TestLT(t *testing.T) {
	tests := []struct {
		name string
		a, b uint32
		want bool
	}{
		{"simple lt", 1, 2, true},
		{"simple gt", 2, 1, false},
		{"equal", 5, 5, false},
		{"wrap lt", 0xFFFFFFFF, 0, true},       // 4294967295 < 0 in wrapping sense
		{"wrap lt 2", 0xFFFFFFFE, 1, true},     // -3 < 0
		{"wrap gt", 0, 0xFFFFFFFF, false},      // 0 > 4294967295? no, 1 > -1 => true? let's check: int32(0 - 0xFFFFFFFF)=int32(1)=1 >0 so GT. So LT should be false. correct.
		{"just over half", 0, 0x80000000, true}, // 0 < 2^31 => int32(-0x80000000) = -2147483648 <0 true
		// 2^31 distance is ambiguous in wrapping arithmetic (int32 overflow);
		// int32(a-b) == -2147483648 for both directions, so LT returns true
		// for both. This is undefined per RFC 793; window sizes must be <2^31.
		{"half boundary", 0x80000000, 0, true},
	}
	for _, tc := range tests {
		if got := LT(tc.a, tc.b); got != tc.want {
			t.Errorf("%s: LT(%d,%d)=%v want %v", tc.name, tc.a, tc.b, got, tc.want)
		}
	}
}

func TestGT(t *testing.T) {
	if !GT(1, 0) {
		t.Error("GT 1,0 want true")
	}
	if GT(0xFFFFFFFF, 0) {
		t.Error("GT wrap 0xFFFFFFFF,0 want false")
	}
	if !GT(0, 0xFFFFFFFF) {
		t.Error("GT 0, 0xFFFFFFFF want true (1 ahead)")
	}
}

func TestLTE_GTE(t *testing.T) {
	if !LTE(5, 5) {
		t.Error("LTE equal")
	}
	if !GTE(5, 5) {
		t.Error("GTE equal")
	}
	if !LTE(0xFFFFFFFF, 0) {
		t.Error("LTE wrap")
	}
	if !GTE(0, 0xFFFFFFFF) {
		t.Error("GTE 0, 0xFFFFFFFF")
	}
}

func TestBetween(t *testing.T) {
	tests := []struct {
		seq, start, end uint32
		want            bool
	}{
		{5, 1, 10, true},
		{10, 1, 10, false}, // end exclusive
		{1, 1, 10, true},
		{0, 1, 10, false},
		{0, 0xFFFFFFFE, 2, true},    // wraps: interval [FFFFFFFE, 2) contains 0xFFFFFFFF, 0, 1
		{0xFFFFFFFE, 0xFFFFFFFE, 2, true},
		{2, 0xFFFFFFFE, 2, false},
		{5, 5, 5, false}, // empty interval
	}
	for _, tc := range tests {
		if got := Between(tc.seq, tc.start, tc.end); got != tc.want {
			t.Errorf("Between(%d,%d,%d)=%v want %v", tc.seq, tc.start, tc.end, got, tc.want)
		}
	}
}

func TestAddSub(t *testing.T) {
	if got := Add(0xFFFFFFFF, 1); got != 0 {
		t.Errorf("Add wrap got %d want 0", got)
	}
	if got := Sub(0, 0xFFFFFFFF); got != 1 {
		t.Errorf("Sub got %d want 1", got)
	}
	if got := Sub(10, 5); got != 5 {
		t.Errorf("Sub 10-5 got %d", got)
	}
}
