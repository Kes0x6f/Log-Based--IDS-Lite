package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/helper"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

type SSHInvalidUserRule struct {
	Threshold int
	Window    time.Duration
}

func NewSSHInvalidUserRule() *SSHInvalidUserRule {
	return &SSHInvalidUserRule{
		Threshold: 5,
		Window:    2 * time.Minute,
	}
}

func (r *SSHInvalidUserRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource: "auth",
		Program:   "sshd",
		EventTypes: []string{
			"SSH_INVALID_USER",
		},
	}
}

func (r *SSHInvalidUserRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {

	s := ctx.SSH
	ip := event.SourceIP
	now := event.Timestamp

	// initialize if needed
	if s.InvalidUserAttempts[ip] == nil {
		s.InvalidUserAttempts[ip] = []time.Time{}
	}

	// track attempts
	for i := 0; i < event.EventCount; i++ {
		s.InvalidUserAttempts[ip] = append(s.InvalidUserAttempts[ip], now)
	}

	// prune old entries (sliding window)
	s.InvalidUserAttempts[ip] = helper.PruneOld(s.InvalidUserAttempts[ip], now, r.Window)

	// threshold check
	if len(s.InvalidUserAttempts[ip]) >= r.Threshold {

		last := s.LastInvalidUserAlert[ip]

		if now.Sub(last) > r.Window {

			alert := model.NewAlert(
				"Invalid User Brute Force",
				model.SeverityMedium,
				"authentication",
				fmt.Sprintf("Multiple invalid user attempts from %s", ip),
				event,
				len(s.InvalidUserAttempts[ip]),
			)

			s.LastInvalidUserAlert[ip] = now

			return []*model.Alert{alert}
		}
	}

	return nil
}
