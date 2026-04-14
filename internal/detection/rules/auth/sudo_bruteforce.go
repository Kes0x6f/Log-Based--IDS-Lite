package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/helper"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

type SudoBruteForceRule struct {
	Threshold int
	Window    time.Duration
}

func NewSudoBruteForceRule() *SudoBruteForceRule {
	return &SudoBruteForceRule{
		Threshold: 5,
		Window:    2 * time.Minute,
	}
}

func (r *SudoBruteForceRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource: "auth",
		Program:   "sudo",
		EventTypes: []string{
			"SUDO_FAIL",
		},
	}
}

func (r *SudoBruteForceRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {

	s := ctx.Sudo
	user := event.Username
	now := event.Timestamp

	if user == "" {
		return nil
	}

	// initialize if needed
	if s.FailedByUser[user] == nil {
		s.FailedByUser[user] = []time.Time{}
	}

	// track failures
	for i := 0; i < event.EventCount; i++ {
		s.FailedByUser[user] = append(s.FailedByUser[user], now)
	}

	// prune old entries (sliding window)
	s.FailedByUser[user] = helper.PruneOld(s.FailedByUser[user], now, r.Window)

	// threshold check
	if len(s.FailedByUser[user]) >= r.Threshold {

		last := s.LastBruteForceAlert[user]

		if now.Sub(last) > r.Window {

			alert := model.NewAlert(
				"SUDO Brute Force",
				model.SeverityHigh,
				"privilege",
				fmt.Sprintf("Multiple failed sudo attempts by user %s", user),
				event,
				len(s.FailedByUser[user]),
			)

			s.LastBruteForceAlert[user] = now

			return []*model.Alert{alert}
		}
	}

	return nil
}
