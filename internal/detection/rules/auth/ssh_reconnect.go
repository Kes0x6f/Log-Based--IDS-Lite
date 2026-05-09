package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/helper"
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
		LogSource:   "auth",
		Program:     "sshd",
		EventTypes:  []string{"SSH_DISCONNECT"},
		DisplayName: "SSH Rapid Reconnect Attack",
		Description: "Frequent disconnect-reconnect cycles from the same IP — automated tool signature.",
		Defaults: detection.RuleDefaults{
			Threshold:   3,
			WindowSec:   120,
			CooldownSec: 120,
		},
	}
}

type sshReconnectState struct {
	disconnectsByIP    map[string][]time.Time
	lastReconnectAlert map[string]time.Time
	// cooldown fix fields
	lastAlertID  map[string]string
	runningCount map[string]int
}

func newSSHReconnectState() *sshReconnectState {
	return &sshReconnectState{
		disconnectsByIP:    make(map[string][]time.Time),
		lastReconnectAlert: make(map[string]time.Time),
		lastAlertID:        make(map[string]string),
		runningCount:       make(map[string]int),
	}
}

// typed accessor — initialises on first call, no rule ever calls SetPrivate directly
func getSSHReconnectState(ctx *context.DetectionContext) *sshReconnectState {
	if v, ok := ctx.GetPrivate("ssh_reconnect"); ok {
		return v.(*sshReconnectState)
	}
	s := newSSHReconnectState()
	ctx.SetPrivate("ssh_reconnect", s)
	return s
}

func (r *SSHReconnectRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext, cfg detection.ResolvedConfig) []*model.Alert {

	s := getSSHReconnectState(ctx)
	ip := event.SourceIP
	now := event.Timestamp

	// initialize if needed
	if s.disconnectsByIP[ip] == nil {
		s.disconnectsByIP[ip] = []time.Time{}
	}

	// track disconnects
	for i := 0; i < event.EventCount; i++ {
		s.disconnectsByIP[ip] = append(s.disconnectsByIP[ip], now)
	}

	// prune old entries (sliding window)
	s.disconnectsByIP[ip] = helper.PruneOld(s.disconnectsByIP[ip], now, cfg.Window)

	if len(s.disconnectsByIP[ip]) < cfg.Threshold {
		return nil
	}

	last := s.lastReconnectAlert[ip]
	inCooldown := !last.IsZero() && now.Sub(last) <= cfg.Cooldown

	if inCooldown {
		s.runningCount[ip] += event.EventCount

		originalID := s.lastAlertID[ip]
		if originalID != "" {
			updatedCount := len(s.disconnectsByIP[ip])
			return []*model.Alert{{
				IsUpdate:        true,
				OriginalAlertID: originalID,
				EventCount:      updatedCount,
			}}
		}
		return nil
	}

	totalCount := len(s.disconnectsByIP[ip])
	newAlert := model.NewAlert(
		"SSH Rapid Reconnect Attack",
		model.SeverityHigh,
		"authentication",
		fmt.Sprintf("Frequent reconnect attempts from %s", ip),
		event,
		totalCount,
	)

	s.lastReconnectAlert[ip] = now
	s.lastAlertID[ip] = newAlert.ID
	s.runningCount[ip] = 0

	return []*model.Alert{newAlert}
}
