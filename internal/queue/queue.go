// SPDX-License-Identifier: AGPL-3.0-only

// Package queue — очередь кадров, ждущих квитанции шлюза (InboundAck): метрики и события агента (E08).
// Элемент лежит, пока канал не отметит доставку; лишние по сроку или по числу вытесняются, самые старые первыми.
package queue

import "sync"

// Item — элемент очереди. ID растёт с каждым Add; по нему канал отмечает доставку.
type Item[T any] struct {
	ID    uint64
	Value T
}

// Queue — очередь с квитанциями. Keep решает, жив ли элемент (срок хранения); nil — живы все.
type Queue[T any] struct {
	mu     sync.Mutex
	items  []Item[T]
	next   uint64
	max    int
	keep   func(T) bool
	notify chan struct{}
}

// New — очередь не длиннее max элементов (max ≤ 0 — без предела по числу).
func New[T any](max int, keep func(T) bool) *Queue[T] {
	return &Queue[T]{max: max, keep: keep, notify: make(chan struct{}, 1)}
}

// Add кладёт элемент и будит отправителя. Возвращает, сколько старых элементов вытеснено.
func (q *Queue[T]) Add(v T) int {
	q.mu.Lock()
	q.next++
	q.items = append(q.items, Item[T]{ID: q.next, Value: v})
	n := q.pruneLocked()
	q.mu.Unlock()
	select {
	case q.notify <- struct{}{}:
	default:
	}
	return n
}

// Pending — недоставленные элементы по порядку.
func (q *Queue[T]) Pending() []Item[T] {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.pruneLocked()
	return append([]Item[T](nil), q.items...)
}

// Ack убирает доставленный элемент; неизвестный номер ничего не меняет.
func (q *Queue[T]) Ack(id uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, it := range q.items {
		if it.ID == id {
			q.items = append(q.items[:i], q.items[i+1:]...)
			return
		}
	}
}

// Notify — сигнал «появился элемент» (один читатель — текущая сессия канала).
func (q *Queue[T]) Notify() <-chan struct{} { return q.notify }

// Len — сколько элементов ждёт доставки.
func (q *Queue[T]) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

func (q *Queue[T]) pruneLocked() int {
	i := 0
	if q.keep != nil {
		for i < len(q.items) && !q.keep(q.items[i].Value) {
			i++
		}
	}
	if q.max > 0 && len(q.items)-i > q.max {
		i = len(q.items) - q.max
	}
	if i > 0 {
		q.items = append([]Item[T](nil), q.items[i:]...)
	}
	return i
}
