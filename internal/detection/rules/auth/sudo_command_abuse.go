package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/helper"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

type SudoCommandAbuseRule struct {
	Threshold int
	Window    time.Duration
}

func NewSudoCommandAbuseRule() *SudoCommandAbuseRule {
	return &SudoCommandAbuseRule{
		Threshold: 5,
		Window:    2 * time.Minute,
	}
}

func (r *SudoCommandAbuseRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource: "auth",
		Program:   "sudo",
		EventTypes: []string{
			"SUDO_EXEC",
		},
	}
}

func (r *SudoCommandAbuseRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {

	s := ctx.Sudo
	user := event.Username
	now := event.Timestamp

	if user == "" {
		return nil
	}

	// initialize map if needed
	if s.CommandsByUser == nil {
		s.CommandsByUser = make(map[string][]time.Time)
	}

	// track execution
	s.CommandsByUser[user] = append(s.CommandsByUser[user], now)

	// prune old entries
	s.CommandsByUser[user] = helper.PruneOld(s.CommandsByUser[user], now, r.Window)

	count := len(s.CommandsByUser[user])

	if count >= r.Threshold {

		last := s.LastAbuseAlert[user]

		// cooldown to avoid spam
		if now.Sub(last) > r.Window {

			alert := model.NewAlert(
				"SUDO Command Abuse",
				model.SeverityHigh,
				"privilege",
				fmt.Sprintf(
					"User %s executed %d sudo commands within %v",
					user,
					count,
					r.Window,
				),
				event,
				count,
			)

			s.LastAbuseAlert[user] = now

			return []*model.Alert{alert}
		}
	}

	return nil
}
