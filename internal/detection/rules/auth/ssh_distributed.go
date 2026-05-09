package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

type SSHDistributedBruteForceRule struct {
	Threshold int
	Window    time.Duration
}

func NewSSHDistributedBruteForceRule() *SSHDistributedBruteForceRule {
	return &SSHDistributedBruteForceRule{
		Threshold: 3, // number of IPs
		Window:    3 * time.Minute,
	}
}

func (r *SSHDistributedBruteForceRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:   "auth",
		Program:     "sshd",
		EventTypes:  []string{"SSH_FAILED", "SSH_INVALID_USER"},
		DisplayName: "Distributed Brute Force",
		Description: "Three or more distinct IPs all failing against the same username — coordinated attack.",
		Defaults: detection.RuleDefaults{
			Threshold:   3,
			WindowSec:   180,
			CooldownSec: 180,
		},
	}
}

type sshDistributedState struct {
	ipsByUser            map[string]map[string]time.Time
	lastDistributedAlert map[string]time.Time
	// cooldown fix fields
	lastAlertID  map[string]string
	runningCount map[string]int
}

func newSSHDistributedState() *sshDistributedState {
	return &sshDistributedState{
		ipsByUser:            make(map[string]map[string]time.Time),
		lastDistributedAlert: make(map[string]time.Time),
		lastAlertID:          make(map[string]string),
		runningCount:         make(map[string]int),
	}
}

// typed accessor — initialises on first call, no rule ever calls SetPrivate directly
func getSSHDistributedState(ctx *context.DetectionContext) *sshDistributedState {
	if v, ok := ctx.GetPrivate("ssh_distributed"); ok {
		return v.(*sshDistributedState)
	}
	s := newSSHDistributedState()
	ctx.SetPrivate("ssh_distributed", s)
	return s
}

func (r *SSHDistributedBruteForceRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext, cfg detection.ResolvedConfig) []*model.Alert {

	s := getSSHDistributedState(ctx)
	ip := event.SourceIP
	user := event.Username
	now := event.Timestamp

	// need a user to track
	if user == "" {
		return nil
	}

	// initialize map if needed
	if s.ipsByUser[user] == nil {
		s.ipsByUser[user] = make(map[string]time.Time)
	}

	// record this IP attacking this user
	s.ipsByUser[user][ip] = now

	// prune old IPs (outside time window)
	for k, t := range s.ipsByUser[user] {
		if now.Sub(t) > r.Window {
			delete(s.ipsByUser[user], k)
		}
	}

	if len(s.ipsByUser[user]) < r.Threshold {
		return nil
	}

	last := s.lastDistributedAlert[user]
	inCooldown := !last.IsZero() && now.Sub(last) <= r.Window

	if inCooldown {
		s.runningCount[user] += event.EventCount

		originalID := s.lastAlertID[user]
		if originalID != "" {
			updatedCount := len(s.ipsByUser[user])
			return []*model.Alert{{
				IsUpdate:        true,
				OriginalAlertID: originalID,
				EventCount:      updatedCount,
			}}
		}
		return nil
	}

	totalCount := len(s.ipsByUser[user])
	newAlert := model.NewAlert(
		"Distributed Brute Force",
		model.SeverityHigh,
		"authentication",
		fmt.Sprintf("Multiple IPs targeting user %s", user),
		event,
		totalCount,
	)
	s.lastDistributedAlert[user] = now
	s.lastAlertID[user] = newAlert.ID
	s.runningCount[user] = 0

	return []*model.Alert{newAlert}
}
