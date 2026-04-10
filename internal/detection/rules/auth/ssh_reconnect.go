package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

type SSHReconnectRule struct {
	Threshold int
	Window    time.Duration
}

func NewSSHReconnectRule() *SSHReconnectRule {
	return &SSHReconnectRule{
		Threshold: 3,
		Window:    2 * time.Minute,
	}
}

func (r *SSHReconnectRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource: "auth",
		Program:   "sshd",
		EventTypes: []string{
			"SSH_DISCONNECT",
		},
	}
}

func (r *SSHReconnectRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {

	s := ctx.SSH
	ip := event.SourceIP
	now := event.Timestamp

	// initialize if needed
	if s.DisconnectsByIP[ip] == nil {
		s.DisconnectsByIP[ip] = []time.Time{}
	}

	// track disconnects
	for i := 0; i < event.EventCount; i++ {
		s.DisconnectsByIP[ip] = append(s.DisconnectsByIP[ip], now)
	}

	// prune old entries (sliding window)
	s.DisconnectsByIP[ip] = s.PruneOld(s.DisconnectsByIP[ip], now, r.Window)

	// threshold check
	if len(s.DisconnectsByIP[ip]) >= r.Threshold {

		last := s.LastReconnectAlert[ip]

		if now.Sub(last) > r.Window {

			alert := model.NewAlert(
				"SSH Rapid Reconnect Attack",
				model.SeverityHigh,
				"authentication",
				fmt.Sprintf("Frequent reconnect attempts from %s", ip),
				event,
				len(s.DisconnectsByIP[ip]),
			)

			s.LastReconnectAlert[ip] = now

			return []*model.Alert{alert}
		}
	}

	return nil
}
