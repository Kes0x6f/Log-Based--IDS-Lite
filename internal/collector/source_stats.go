package collector

import (
	"sync"
	"time"
)

// SourceStat holds runtime counters for a single watched file.
type SourceStat struct {
	LinesTotal   int64     `json:"lines_total"`
	LastEventAt  time.Time `json:"last_event_at"`
	WatcherAlive bool      `json:"watcher_alive"`
}

// SourceStats is a thread-safe registry of per-source counters.
// One shared instance is created in main and passed to every FileCollector
// and to the API Handler so the /sources/status endpoint can serve it.
type SourceStats struct {
	mu    sync.RWMutex
	stats map[string]*SourceStat
}

func NewSourceStats() *SourceStats {
	return &SourceStats{
		stats: make(map[string]*SourceStat),
	}
}

func (s *SourceStats) getOrCreate(source string) *SourceStat {
	if s.stats[source] == nil {
		s.stats[source] = &SourceStat{}
	}
	return s.stats[source]
}

// RecordLine increments the line counter and records the current time.
// Called by FileCollector every time a complete log line is emitted.
func (s *SourceStats) RecordLine(source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.getOrCreate(source)
	st.LinesTotal++
	st.LastEventAt = time.Now()
	st.WatcherAlive = true
}

// SetWatcherAlive marks whether the fsnotify watcher for source is healthy.
func (s *SourceStats) SetWatcherAlive(source string, alive bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.getOrCreate(source).WatcherAlive = alive
}

// Snapshot returns a point-in-time copy of all source stats.
func (s *SourceStats) Snapshot() map[string]SourceStat {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]SourceStat, len(s.stats))
	for k, v := range s.stats {
		out[k] = *v
	}
	return out
}
