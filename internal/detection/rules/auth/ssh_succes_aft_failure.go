package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

type SSHSuccessAfterFailRule struct {
	Window    time.Duration
	Threshold int
}

func NewSSHSuccessAfterFailRule() *SSHSuccessAfterFailRule {
	return &SSHSuccessAfterFailRule{
		Window:    5 * time.Minute,
		Threshold: 3,
	}
}

func (r *SSHSuccessAfterFailRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource: "auth",
		Program:   "sshd",
		EventTypes: []string{
			"SSH_FAILED",
			"SSH_SUCCESS",
		},
	}
}

func (r *SSHSuccessAfterFailRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {

	s := ctx.SSH
	ip := event.SourceIP
	now := event.Timestamp

	switch event.EventType {

	// -------------------------
	// TRACK FAILURES
	// -------------------------
	case "SSH_FAILED", "SSH_INVALID_USER":

		s.RecentFailures[ip] = append(s.RecentFailures[ip], now)

		// prune old entries
		s.RecentFailures[ip] = s.PruneOld(s.RecentFailures[ip], now, r.Window)

		return nil

	// -------------------------
	// DETECT SUCCESS AFTER FAIL
	// -------------------------
	case "SSH_SUCCESS":

		failures := s.RecentFailures[ip]

		if len(failures) >= r.Threshold {

			last := s.LastSuspiciousLoginAlert[ip]

			if now.Sub(last) > r.Window {

				alert := model.NewAlert(
					"SSH Suspicious Login",
					model.SeverityCritical,
					"authentication",
					fmt.Sprintf(
						"SSH login succeeded after %d failed attempts from %s",
						len(failures),
						ip,
					),
					event,
					len(failures),
				)

				s.LastSuspiciousLoginAlert[ip] = now

				// reset after success
				delete(s.RecentFailures, ip)

				return []*model.Alert{alert}
			}
		}

		// reset even if below threshold (clean state)
		delete(s.RecentFailures, ip)
	}

	return nil
}
