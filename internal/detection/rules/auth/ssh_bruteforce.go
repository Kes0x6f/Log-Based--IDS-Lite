package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

type SSHBruteForceRule struct {
	Threshold int
	Window    time.Duration
}

func NewSSHBruteForceRule() *SSHBruteForceRule {
	return &SSHBruteForceRule{
		Threshold: 5,
		Window:    2 * time.Minute,
	}
}

func (r *SSHBruteForceRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource: "auth",
		Program:   "sshd",
		EventTypes: []string{
			"SSH_FAILED",
		},
	}
}

func (r *SSHBruteForceRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {

	s := ctx.SSH
	ip := event.SourceIP
	now := event.Timestamp

	for i := 0; i < event.EventCount; i++ {
		s.FailedByIP[ip] = append(s.FailedByIP[ip], now)
	}

	s.FailedByIP[ip] = s.PruneOld(s.FailedByIP[ip], now, r.Window)

	if len(s.FailedByIP[ip]) >= r.Threshold {
		last := s.LastBruteForceAlert[ip]
		if now.Sub(last) > r.Window {

			alert := model.NewAlert(
				"SSH Brute Force",
				model.SeverityHigh,
				"authentication",
				fmt.Sprintf("Multiple failed SSH login attempts from %s", ip),
				event,
				len(s.FailedByIP[ip]),
			)

			s.LastBruteForceAlert[ip] = now
			return []*model.Alert{alert}
		}
	}

	return nil
}
