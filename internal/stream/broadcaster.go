package stream

import "sync"

type Broadcaster struct {
	subscribers []chan string
	mu          sync.Mutex
}

func NewBroadcaster() *Broadcaster {
	return &Broadcaster{
		subscribers: []chan string{},
	}
}

func (b *Broadcaster) Subscribe() chan string {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan string, 100)
	b.subscribers = append(b.subscribers, ch)
	return ch
}

func (b *Broadcaster) Publish(msg string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, ch := range b.subscribers {
		select {
		case ch <- msg:
		default:
		}
	}
}
