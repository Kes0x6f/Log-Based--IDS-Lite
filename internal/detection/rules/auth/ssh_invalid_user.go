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
		LogSource:   "auth",
		Program:     "sshd",
		EventTypes:  []string{"SSH_INVALID_USER"},
		DisplayName: "Invalid User Brute Force",
		Description: "Repeated SSH attempts for usernames that do not exist on the system.",
		Defaults: detection.RuleDefaults{
			Threshold:   5,
			WindowSec:   120,
			CooldownSec: 120,
		},
	}
}

type sshInvalidUserState struct {
	invalidUserAttempts  map[string][]time.Time
	lastInvalidUserAlert map[string]time.Time
	// cooldown fix fields
	lastAlertID  map[string]string
	runningCount map[string]int
}

func newSSHInvalidUserState() *sshInvalidUserState {
	return &sshInvalidUserState{
		invalidUserAttempts:  make(map[string][]time.Time),
		lastInvalidUserAlert: make(map[string]time.Time),
		lastAlertID:          make(map[string]string),
		runningCount:         make(map[string]int),
	}
}

// typed accessor — initialises on first call, no rule ever calls SetPrivate directly
func getSSHInvalidUserState(ctx *context.DetectionContext) *sshInvalidUserState {
	if v, ok := ctx.GetPrivate("ssh_invalid_user"); ok {
		return v.(*sshInvalidUserState)
	}
	s := newSSHInvalidUserState()
	ctx.SetPrivate("ssh_invalid_user", s)
	return s
}

func (r *SSHInvalidUserRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext, cfg detection.ResolvedConfig) []*model.Alert {

	s := getSSHInvalidUserState(ctx)
	ip := event.SourceIP
	now := event.Timestamp

	// initialize if needed
	if s.invalidUserAttempts[ip] == nil {
		s.invalidUserAttempts[ip] = []time.Time{}
	}

	// track attempts
	for i := 0; i < event.EventCount; i++ {
		s.invalidUserAttempts[ip] = append(s.invalidUserAttempts[ip], now)
	}

	// prune old entries (sliding window)
	s.invalidUserAttempts[ip] = helper.PruneOld(s.invalidUserAttempts[ip], now, cfg.Window)

	if len(s.invalidUserAttempts[ip]) < cfg.Threshold {
		return nil
	}
	last := s.lastInvalidUserAlert[ip]
	inCooldown := !last.IsZero() && now.Sub(last) <= cfg.Cooldown

	if inCooldown {
		s.runningCount[ip] += event.EventCount

		originalID := s.lastAlertID[ip]
		if originalID != "" {
			updatedCount := len(s.invalidUserAttempts[ip])
			return []*model.Alert{{
				IsUpdate:        true,
				OriginalAlertID: originalID,
				EventCount:      updatedCount,
			}}
		}
		return nil
	}

	totalCount := len(s.invalidUserAttempts[ip])
	event.TargetUser = event.Username
	newAlert := model.NewAlert(
		"Invalid User Brute Force",
		model.SeverityMedium,
		"authentication",
		fmt.Sprintf("SSH invalid-user brute force from %s: %d attempts in %v, user: %s", ip, totalCount, r.Window, event.Username),
		event,
		totalCount,
	)

	s.lastInvalidUserAlert[ip] = now
	s.lastAlertID[ip] = newAlert.ID
	s.runningCount[ip] = 0

	return []*model.Alert{newAlert}
}
