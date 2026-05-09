package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/helper"
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
		LogSource:   "auth",
		Program:     "sshd",
		EventTypes:  []string{"SSH_FAILED"},
		DisplayName: "SSH Brute Force",
		Description: "Multiple failed SSH login attempts from a single IP within a sliding window.",
		Defaults: detection.RuleDefaults{
			Threshold:   5,
			WindowSec:   120,
			CooldownSec: 120,
		},
	}
}

type sshBruteState struct {
	failedByIP    map[string][]time.Time
	lastAlertByIP map[string]time.Time
	// cooldown fix fields
	lastAlertID  map[string]string
	runningCount map[string]int
}

func newSSHBruteState() *sshBruteState {
	return &sshBruteState{
		failedByIP:    make(map[string][]time.Time),
		lastAlertByIP: make(map[string]time.Time),
		lastAlertID:   make(map[string]string),
		runningCount:  make(map[string]int),
	}
}

// typed accessor — initialises on first call, no rule ever calls SetPrivate directly
func getSSHBruteState(ctx *context.DetectionContext) *sshBruteState {
	if v, ok := ctx.GetPrivate("ssh_brute"); ok {
		return v.(*sshBruteState)
	}
	s := newSSHBruteState()
	ctx.SetPrivate("ssh_brute", s)
	return s
}

func (r *SSHBruteForceRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext, cfg detection.ResolvedConfig) []*model.Alert {

	s := getSSHBruteState(ctx)
	ip := event.SourceIP
	now := event.Timestamp

	for i := 0; i < event.EventCount; i++ {
		s.failedByIP[ip] = append(s.failedByIP[ip], now)
	}

	s.failedByIP[ip] = helper.PruneOld(s.failedByIP[ip], now, cfg.Window)

	if len(s.failedByIP[ip]) < cfg.Threshold {
		return nil
	}

	last := s.lastAlertByIP[ip]
	inCooldown := !last.IsZero() && now.Sub(last) <= cfg.Cooldown

	if inCooldown {
		s.runningCount[ip] += event.EventCount

		originalID := s.lastAlertID[ip]
		if originalID != "" {
			updatedCount := len(s.failedByIP[ip])
			return []*model.Alert{{
				IsUpdate:        true,
				OriginalAlertID: originalID,
				EventCount:      updatedCount,
			}}
		}
		return nil
	}

	totalCount := len(s.failedByIP[ip])

	newAlert := model.NewAlert(
		"SSH Brute Force",
		model.SeverityHigh,
		"authentication",
		fmt.Sprintf("Multiple failed SSH login attempts from %s", ip),
		event,
		totalCount,
	)

	s.lastAlertByIP[ip] = now
	s.lastAlertID[ip] = newAlert.ID
	s.runningCount[ip] = 0

	return []*model.Alert{newAlert}
}
