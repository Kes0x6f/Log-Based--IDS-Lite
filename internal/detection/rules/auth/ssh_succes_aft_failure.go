package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/helper"
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
		LogSource:   "auth",
		Program:     "sshd",
		EventTypes:  []string{"SSH_FAILED", "SSH_SUCCESS"},
		DisplayName: "SSH Suspicious Login",
		Description: "Successful SSH login preceded by multiple failures — likely brute-force success.",
		Defaults: detection.RuleDefaults{
			Threshold:   3,
			WindowSec:   300,
			CooldownSec: 300,
		},
	}
}

type sshSuccessAfterFailState struct {
	recentFailures           map[string][]time.Time
	lastSuspiciousLoginAlert map[string]time.Time
	// cooldown fix fields
	lastAlertID  map[string]string
	runningCount map[string]int
}

func newSSHSuccessAfterFailState() *sshSuccessAfterFailState {
	return &sshSuccessAfterFailState{
		recentFailures:           make(map[string][]time.Time),
		lastSuspiciousLoginAlert: make(map[string]time.Time),
		lastAlertID:              make(map[string]string),
		runningCount:             make(map[string]int),
	}
}

// typed accessor — initialises on first call, no rule ever calls SetPrivate directly
func getSSHSuccessAfterFailState(ctx *context.DetectionContext) *sshSuccessAfterFailState {
	if v, ok := ctx.GetPrivate("ssh_success_after_fail"); ok {
		return v.(*sshSuccessAfterFailState)
	}
	s := newSSHSuccessAfterFailState()
	ctx.SetPrivate("ssh_success_after_fail", s)
	return s
}

func (r *SSHSuccessAfterFailRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext, cfg detection.ResolvedConfig) []*model.Alert {

	s := getSSHSuccessAfterFailState(ctx)
	ip := event.SourceIP
	now := event.Timestamp

	switch event.EventType {

	case "SSH_FAILED", "SSH_INVALID_USER":

		s.recentFailures[ip] = append(s.recentFailures[ip], now)

		// prune old entries
		s.recentFailures[ip] = helper.PruneOld(s.recentFailures[ip], now, cfg.Window)

		return nil

	case "SSH_SUCCESS":

		failures := s.recentFailures[ip]

		if len(failures) >= cfg.Threshold {

			last := s.lastSuspiciousLoginAlert[ip]

			if now.Sub(last) > cfg.Cooldown {

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

				s.lastSuspiciousLoginAlert[ip] = now

				// reset after success
				delete(s.recentFailures, ip)

				return []*model.Alert{alert}
			}
		}

		// reset even if below threshold (clean state)
		delete(s.recentFailures, ip)
	}

	return nil
}
