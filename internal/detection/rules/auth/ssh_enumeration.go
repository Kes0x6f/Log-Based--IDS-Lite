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
		LogSource:   "auth",
		Program:     "sshd",
		EventTypes:  []string{"SSH_FAILED", "SSH_INVALID_USER"},
		DisplayName: "SSH Username Enumeration",
		Description: "Single IP attempting many distinct usernames — automated user discovery.",
		Defaults: detection.RuleDefaults{
			Threshold:   5,
			WindowSec:   180,
			CooldownSec: 180,
		},
	}
}

type sshEnumerationState struct {
	failedUsersByIP      map[string]map[string]time.Time
	lastEnumerationAlert map[string]time.Time
	// cooldown fix fields
	lastAlertID  map[string]string
	runningCount map[string]int
}

func newSSHEnumerationState() *sshEnumerationState {
	return &sshEnumerationState{
		failedUsersByIP:      make(map[string]map[string]time.Time),
		lastEnumerationAlert: make(map[string]time.Time),
		lastAlertID:          make(map[string]string),
		runningCount:         make(map[string]int),
	}
}

// typed accessor — initialises on first call, no rule ever calls SetPrivate directly
func getEnumerationState(ctx *context.DetectionContext) *sshEnumerationState {
	if v, ok := ctx.GetPrivate("ssh_enumeration"); ok {
		return v.(*sshEnumerationState)
	}
	s := newSSHEnumerationState()
	ctx.SetPrivate("ssh_enumeration", s)
	return s
}

func (r *SSHEnumerationRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext, cfg detection.ResolvedConfig) []*model.Alert {

	s := getEnumerationState(ctx)
	ip := event.SourceIP
	user := event.Username
	now := event.Timestamp

	if user == "" {
		return nil
	}

	if s.failedUsersByIP[ip] == nil {
		s.failedUsersByIP[ip] = make(map[string]time.Time)
	}

	s.failedUsersByIP[ip][user] = now
	s.PruneUserEnumeration(ip, now, cfg.Window)

	if len(s.failedUsersByIP[ip]) < cfg.Threshold {
		return nil
	}

	last := s.lastEnumerationAlert[ip]
	inCooldown := !last.IsZero() && now.Sub(last) <= cfg.Cooldown

	if inCooldown {
		s.runningCount[ip] += event.EventCount

		originalID := s.lastAlertID[ip]
		if originalID != "" {
			updatedCount := len(s.failedUsersByIP[ip])
			return []*model.Alert{{
				IsUpdate:        true,
				OriginalAlertID: originalID,
				EventCount:      updatedCount,
			}}
		}
		return nil
	}

	totalCount := len(s.failedUsersByIP[ip])
	newAlert := model.NewAlert(
		"SSH Username Enumeration",
		model.SeverityHigh,
		"authentication",
		fmt.Sprintf("Multiple username attempts from %s", ip),
		event,
		totalCount,
	)
	s.lastEnumerationAlert[ip] = now
	s.lastAlertID[ip] = newAlert.ID
	s.runningCount[ip] = 0

	return []*model.Alert{newAlert}
}

func (s *sshEnumerationState) PruneUserEnumeration(ip string, now time.Time, window time.Duration) {

	users := s.failedUsersByIP[ip]

	for user, t := range users {
		if now.Sub(t) > window {
			delete(users, user)
		}
	}
}
