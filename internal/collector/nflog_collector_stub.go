//go:build !linux

package collector

import (
	"context"
	"log"

	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
	"github.com/Kes0x6f/Log-Based--IDS/internal/stream"
)

// NFLOGCollector is a no-op stub on non-Linux platforms.
// The real implementation lives in nflog_collector.go (Linux only).
type NFLOGCollector struct {
	Broadcaster *stream.Broadcaster
}

func (c *NFLOGCollector) Start(ctx context.Context, out chan<- *model.NormalizedEvent) {
	log.Println("NFLOGCollector: Linux only — no-op on this platform")
	<-ctx.Done()
}
