package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/helper"
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
		LogSource:   "auth",
		Program:     "sshd",
		EventTypes:  []string{"SSH_FAILED", "SSH_INVALID_USER"},
		DisplayName: "SSH Root Targeting",
		Description: "Failed SSH attempt targeting the root account — fires on first occurrence, then deduplicates within a cooldown window.",
		Defaults: detection.RuleDefaults{
			Threshold:   0,
			WindowSec:   120,
			CooldownSec: 120,
		},
	}
}

type sshRootTargetState struct {
	rootFailures        map[string][]time.Time
	lastRootTargetAlert map[string]time.Time
	lastAlertID         map[string]string
	runningCount        map[string]int
}

func newSSHRootTargetState() *sshRootTargetState {
	return &sshRootTargetState{
		rootFailures:        make(map[string][]time.Time),
		lastRootTargetAlert: make(map[string]time.Time),
		lastAlertID:         make(map[string]string),
		runningCount:        make(map[string]int),
	}
}

func getSSHRootTargetState(ctx *context.DetectionContext) *sshRootTargetState {
	if v, ok := ctx.GetPrivate("ssh_root_target"); ok {
		return v.(*sshRootTargetState)
	}
	s := newSSHRootTargetState()
	ctx.SetPrivate("ssh_root_target", s)
	return s
}

func (r *SSHRootTargetRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext, cfg detection.ResolvedConfig) []*model.Alert {

	s := getSSHRootTargetState(ctx)
	ip := event.SourceIP
	user := event.Username
	now := event.Timestamp

	if user != "root" {
		return nil
	}

	if s.rootFailures[ip] == nil {
		s.rootFailures[ip] = []time.Time{}
	}

	for i := 0; i < event.EventCount; i++ {
		s.rootFailures[ip] = append(s.rootFailures[ip], now)
	}

	s.rootFailures[ip] = helper.PruneOld(s.rootFailures[ip], now, cfg.Window)

	last := s.lastRootTargetAlert[ip]
	inCooldown := !last.IsZero() && now.Sub(last) <= cfg.Cooldown

	if inCooldown {
		originalID := s.lastAlertID[ip]
		if originalID != "" {
			return []*model.Alert{{
				IsUpdate:        true,
				OriginalAlertID: originalID,
				EventCount:      len(s.rootFailures[ip]),
			}}
		}
		return nil
	}

	newAlert := model.NewAlert(
		"SSH Root Targeting",
		model.SeverityHigh,
		"authentication",
		fmt.Sprintf("SSH root account targeted from %s", ip),
		event,
		len(s.rootFailures[ip]),
	)

	s.lastRootTargetAlert[ip] = now
	s.lastAlertID[ip] = newAlert.ID

	return []*model.Alert{newAlert}
}
