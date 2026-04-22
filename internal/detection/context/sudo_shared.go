package context

import "time"

// SharedSudoContext holds state that is intentionally visible across
// multiple sudo rules. Only add fields here when two separate rules
// genuinely need to read each other's observations.
//
// Writer → Reader:
//   CommandsByUser: SudoCommandAbuseRule (writes) → SudoSensitiveCommandRule (reads for scoring)
//   RecentFails:    SudoSuccessAfterFailRule (writes) → SudoSensitiveCommandRule (reads for scoring)
type SharedSudoContext struct {
	CommandsByUser map[string][]time.Time
	RecentFails    map[string][]time.Time
}

func NewSharedSudoContext() *SharedSudoContext {
	return &SharedSudoContext{
		CommandsByUser: make(map[string][]time.Time),
		RecentFails:    make(map[string][]time.Time),
	}
}
