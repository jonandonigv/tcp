// Package retransmit — retransmission queue (RFC 793 §3.7, p.41).
package retransmit

import (
	"time"
)

// Entry is a sent segment awaiting ACK (RFC 793 retransmission queue).
type Entry struct {
	Seq       uint32        // SEG.SEQ of first byte
	Payload   []byte        // data (copied)
	SentAt    time.Time     // last transmission time
	Attempts  int           // retransmission count
}

// Queue holds unacknowledged segments in SND.UNA .. SND.NXT-1 order.
// It is owned by the TCB's goroutine (no concurrent access).
type Queue struct {
	entries []Entry
	// nowFn allows deterministic tests to inject a fake clock.
	nowFn func() time.Time
}

// NewQueue returns an empty queue. nowFn may be nil (uses time.Now).
func NewQueue(nowFn func() time.Time) *Queue {
	return &Queue{nowFn: nowFn}
}

func (q *Queue) now() time.Time {
	if q.nowFn != nil {
		return q.nowFn()
	}
	return time.Now()
}

// Enqueue adds a segment (seq + payload). Payload is copied.
// Caller must ensure seq == SND.NXT prior to advance.
func (q *Queue) Enqueue(seq uint32, payload []byte) {
	cp := make([]byte, len(payload))
	copy(cp, payload)
	q.entries = append(q.entries, Entry{
		Seq:      seq,
		Payload:  cp,
		SentAt:   q.now(),
		Attempts: 1,
	})
}

// Len returns number of unacked segments.
func (q *Queue) Len() int { return len(q.entries) }

// Empty reports whether queue is empty.
func (q *Queue) Empty() bool { return len(q.entries) == 0 }

// Oldest returns the first entry (SND.UNA) or nil.
func (q *Queue) Oldest() *Entry {
	if len(q.entries) == 0 {
		return nil
	}
	return &q.entries[0]
}

// Ack removes all entries fully acknowledged by ack (RFC 793 §3.7).
// An entry is acked if ack >= entry.Seq+entry.Len in sequence space.
// Uses wrapping arithmetic: ack covers seq..seq+len-1 if ack is beyond end.
// Returns number of entries removed.
//
// RFC 793 p.41: SND.UNA ← SEG.ACK, discard acked segments.
func (q *Queue) Ack(ack uint32) int {
	// Remove from front while ack covers entry.
	removed := 0
	for len(q.entries) > 0 {
		e := q.entries[0]
		end := e.Seq + uint32(len(e.Payload))
		// Special case zero-length segment (e.g., pure ACK/FIN): len 0 means seq+0 == seq.
		// For zero-length, ack == end means acked (FIN/SYN each 1 byte would be non-zero len).
		// Use wrapping-aware check: entry covered if ack >= end and ack <=? But we need SND.UNA <= seq < ack?
		// Simpler: ack covers entry if seqLT(seq, ack) or seq==ack && len==0? Better to check seqLT(end, ack) or EQ(end,ack).
		// That is: ack is at or beyond end in sequence space, and entry start is before ack.
		// For queue order, if ack == end, entry is acked. If int32(ack-end) >=0 and int32(e.Seq - q.entries[0].Seq) ... but queue is ordered.
		// We just check ack >= end using int32(ack-end) >=0.
		if len(e.Payload) == 0 {
			// Zero-length: ack must equal seq to ack? But we treat zero-len as ack==seq.
			if ack != e.Seq {
				break
			}
			// covered
		} else {
			// ack >= end ?
			if int32(ack-end) < 0 {
				break
			}
			// Also ensure entry start is before ack: int32(ack-e.Seq) >0 but end check already ensures.
		}
		q.entries = q.entries[1:]
		removed++
	}
	return removed
}

// NeedsRetransmit reports entries whose SentAt+RTO < now (RFC 793 exponential backoff).
// Caller should retransmit the oldest first.
func (q *Queue) NeedsRetransmit(rto time.Duration) []Entry {
	var out []Entry
	now := q.now()
	for i := range q.entries {
		if now.Sub(q.entries[i].SentAt) >= rto {
			out = append(out, q.entries[i])
		}
	}
	return out
}

// Retransmit marks the oldest entry as retransmitted (update SentAt, bump Attempts).
// Returns the entry to resend or nil if empty.
func (q *Queue) Retransmit() *Entry {
	if len(q.entries) == 0 {
		return nil
	}
	q.entries[0].SentAt = q.now()
	q.entries[0].Attempts++
	return &q.entries[0]
}

// Peek returns all entries for inspection (copy).
func (q *Queue) Peek() []Entry {
	out := make([]Entry, len(q.entries))
	copy(out, q.entries)
	return out
}

// Clear empties the queue.
func (q *Queue) Clear() { q.entries = nil }
