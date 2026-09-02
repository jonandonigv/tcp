package retransmit

import (
	"testing"
	"time"
)

func fakeNow(start time.Time) func() time.Time {
	cur := start
	return func() time.Time { return cur }
}

func TestQueueEnqueueAck(t *testing.T) {
	q := NewQueue(nil)
	q.Enqueue(1000, []byte("hello"))
	q.Enqueue(1005, []byte("world"))
	if q.Len() != 2 {
		t.Fatalf("len %d want 2", q.Len())
	}
	// Ack covering first entry only (ack=1005)
	if n := q.Ack(1005); n != 1 {
		t.Errorf("Ack 1005 removed %d want 1 len %d", n, q.Len())
	}
	if q.Len() != 1 || q.Oldest().Seq != 1005 {
		t.Errorf("remaining %+v", q.Peek())
	}
	// Ack covering second
	if n := q.Ack(1010); n != 1 {
		t.Errorf("Ack 1010 removed %d", n)
	}
	if !q.Empty() {
		t.Error("queue should be empty")
	}
	// Ack beyond -> no-op
	q.Enqueue(2000, []byte("x"))
	if n := q.Ack(2000); n != 0 {
		t.Errorf("Ack equal seq with len>0 should not ack, n=%d", n)
	}
	if n := q.Ack(2001); n != 1 {
		t.Errorf("Ack 2001 should ack len1, n=%d", n)
	}
}

func TestQueueAckWrapping(t *testing.T) {
	q := NewQueue(nil)
	q.Enqueue(0xFFFFFFFE, []byte("ab")) // seq 4294967294 len 2 end=0
	if n := q.Ack(0); n != 1 {
		t.Errorf("wrap Ack 0 should ack seq FF FE len2 end 0, removed %d", n)
	}
	q.Enqueue(0xFFFFFFFF, []byte("z")) // end 0
	if n := q.Ack(0); n != 1 {
		t.Errorf("wrap single ack 0 seq FF FF len1 end 0 removed %d", n)
	}
}

func TestQueueNeedsRetransmit(t *testing.T) {
	base := time.Unix(0, 0)
	cur := base
	nowFn := func() time.Time { return cur }
	q := NewQueue(nowFn)
	q.Enqueue(1000, []byte("a"))
	// Advance 500ms, RTO 200ms -> needs retransmit
	cur = base.Add(500 * time.Millisecond)
	need := q.NeedsRetransmit(200 * time.Millisecond)
	if len(need) != 1 {
		t.Errorf("needs retransmit %d want 1", len(need))
	}
	// Fresh entry not yet
	q2 := NewQueue(nowFn)
	q2.Enqueue(2000, []byte("b"))
	cur = base.Add(100 * time.Millisecond) // only 0 elapsed from enqueue? Actually base-> cur 100, but q2 enqueued at 500+? Wait careful: q2 enqueued at cur=500+500? Simplify separate.
	// Instead create new queue with fresh now
	base2 := time.Unix(10, 0)
	cur2 := base2
	q3 := NewQueue(func() time.Time { return cur2 })
	q3.Enqueue(3000, []byte("c"))
	need3 := q3.NeedsRetransmit(200 * time.Millisecond)
	if len(need3) != 0 {
		t.Errorf("fresh should not need retransmit")
	}
	cur2 = cur2.Add(300 * time.Millisecond)
	need3 = q3.NeedsRetransmit(200 * time.Millisecond)
	if len(need3) != 1 {
		t.Error("after 300ms should need")
	}
}

func TestQueueRetransmit(t *testing.T) {
	base := time.Unix(0, 0)
	cur := base
	q := NewQueue(func() time.Time { return cur })
	q.Enqueue(1000, []byte("hi"))
	if e := q.Retransmit(); e == nil || e.Attempts != 2 {
		t.Fatalf("Retransmit attempts %v", e)
	}
	if q.Oldest().SentAt != cur {
		t.Error("SentAt should be updated")
	}
	cur = cur.Add(time.Second)
	e := q.Retransmit()
	if e.Attempts != 3 {
		t.Errorf("attempts %d want 3", e.Attempts)
	}
}

func TestQueueClear(t *testing.T) {
	q := NewQueue(nil)
	q.Enqueue(1, []byte("a"))
	q.Enqueue(2, []byte("b"))
	q.Clear()
	if !q.Empty() {
		t.Error("clear failed")
	}
}
