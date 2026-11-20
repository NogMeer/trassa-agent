// SPDX-License-Identifier: AGPL-3.0-only

package queue

import "testing"

func TestQueue(t *testing.T) {
	alive := map[int]bool{1: true, 2: true, 3: true, 4: true, 5: true}
	q := New(3, func(v int) bool { return alive[v] })
	for v := 1; v <= 3; v++ {
		if n := q.Add(v); n != 0 {
			t.Fatalf("Add(%d) вытеснил %d", v, n)
		}
	}
	select {
	case <-q.Notify():
	default:
		t.Fatal("нет сигнала")
	}
	q.Ack(2)
	q.Ack(99)
	if p := q.Pending(); len(p) != 2 || p[0].Value != 1 || p[1].Value != 3 {
		t.Fatalf("%+v", p)
	}
	// Предел по числу: самый старый вытесняется.
	q.Add(4)
	if n := q.Add(5); n != 1 {
		t.Fatalf("вытеснено %d", n)
	}
	if p := q.Pending(); len(p) != 3 || p[0].Value != 3 || p[0].ID != 3 {
		t.Fatalf("%+v", p)
	}
	// Срок: просроченный в начале очереди уходит.
	alive[3] = false
	if p := q.Pending(); len(p) != 2 || p[0].Value != 4 {
		t.Fatalf("%+v", p)
	}
	if q.Len() != 2 {
		t.Fatal(q.Len())
	}
}
