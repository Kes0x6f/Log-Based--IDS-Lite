package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

type SSHEnumerationRule struct {
	Threshold int
	Window    time.Duration
}

func NewSSHEnumerationRule() *SSHEnumerationRule {
	return &SSHEnumerationRule{
		Threshold: 5,
		Window:    3 * time.Minute,
	}
}

func (r *SSHEnumerationRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource: "auth",
		Program:   "sshd",
		EventTypes: []string{
			"SSH_FAILED",
			"SSH_INVALID_USER",
		},
	}
}

func (r *SSHEnumerationRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {

	s := ctx.SSH
	ip := event.SourceIP
	user := event.Username
	now := event.Timestamp

	if user == "" {
		return nil
	}

	if s.FailedUsersByIP[ip] == nil {
		s.FailedUsersByIP[ip] = make(map[string]time.Time)
	}

	s.FailedUsersByIP[ip][user] = now
	s.PruneUserEnumeration(ip, now, r.Window)

	if len(s.FailedUsersByIP[ip]) >= r.Threshold {
		last := s.LastEnumerationAlert[ip]
		if now.Sub(last) > r.Window {

			alert := model.NewAlert(
				"SSH Username Enumeration",
				model.SeverityHigh,
				"authentication",
				fmt.Sprintf("Multiple username attempts from %s", ip),
				event,
				len(s.FailedUsersByIP[ip]),
			)

			s.LastEnumerationAlert[ip] = now
			return []*model.Alert{alert}
		}
	}

	return nil
}
