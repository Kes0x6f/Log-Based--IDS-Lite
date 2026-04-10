package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

type SSHRootTargetRule struct {
	Window time.Duration
}

func NewSSHRootTargetRule() *SSHRootTargetRule {
	return &SSHRootTargetRule{
		Window: 2 * time.Minute,
	}
}

func (r *SSHRootTargetRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource: "auth",
		Program:   "sshd",
		EventTypes: []string{
			"SSH_FAILED",
			"SSH_INVALID_USER",
		},
	}
}

func (r *SSHRootTargetRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {

	s := ctx.SSH
	ip := event.SourceIP
	user := event.Username
	now := event.Timestamp

	// only care about root
	if user != "root" {
		return nil
	}

	// track root targeting attempts
	if s.RootFailures[ip] == nil {
		s.RootFailures[ip] = []time.Time{}
	}

	for i := 0; i < event.EventCount; i++ {
		s.RootFailures[ip] = append(s.RootFailures[ip], now)
	}

	// prune old entries
	s.RootFailures[ip] = s.PruneOld(s.RootFailures[ip], now, r.Window)

	// cooldown check (prevents spam)
	last := s.LastRootTargetAlert[ip]

	if now.Sub(last) > r.Window {

		alert := model.NewAlert(
			"SSH Root Targeting",
			model.SeverityHigh,
			"authentication",
			fmt.Sprintf("SSH root account targeted from %s", ip),
			event,
			len(s.RootFailures[ip]),
		)

		s.LastRootTargetAlert[ip] = now

		return []*model.Alert{alert}
	}

	return nil
}
