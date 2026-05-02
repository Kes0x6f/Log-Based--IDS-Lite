package stream

import "sync"

// Message carries a log line together with the source tag assigned by
// the FileCollector that read it ("auth", "ufw", "kern", "audit", "apache2", "nginx").
type Message struct {
	Source string
	Line   string
}

type Broadcaster struct {
	subscribers []chan Message
	mu          sync.Mutex
}

func NewBroadcaster() *Broadcaster {
	return &Broadcaster{
		subscribers: []chan Message{},
	}
}

// Subscribe returns a channel that will receive every published Message.
func (b *Broadcaster) Subscribe() chan Message {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan Message, 100)
	b.subscribers = append(b.subscribers, ch)
	return ch
}

// Unsubscribe removes the channel and closes it so the consumer goroutine
// can detect the disconnection and clean up.
func (b *Broadcaster) Unsubscribe(ch chan Message) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for i, sub := range b.subscribers {
		if sub == ch {
			b.subscribers = append(b.subscribers[:i], b.subscribers[i+1:]...)
			close(ch)
			return
		}
	}
}

// Publish sends source + line to every active subscriber.  Slow consumers
// are skipped (the channel is buffered to 100) so a stalled SSE client
// never blocks the collector goroutine.
func (b *Broadcaster) Publish(source, line string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	msg := Message{Source: source, Line: line}
	for _, ch := range b.subscribers {
		select {
		case ch <- msg:
		default:
		}
	}
}
