package detection

import "time"

// RuleDefaults holds the compile-time threshold, window, and cooldown values
// that each rule declares in its Meta() method.
// Rules not yet updated will have zero values here — the engine treats
// zero Defaults as "pass through; rule manages its own state internally."
type RuleDefaults struct {
	Threshold   int
	WindowSec   int
	CooldownSec int
}

// ResolvedConfig is the merged result of a rule's compiled defaults and any
// active database override. The engine computes one per matching rule per event.
type ResolvedConfig struct {
	Threshold int
	Window    time.Duration
	Cooldown  time.Duration
	Enabled   bool
}
