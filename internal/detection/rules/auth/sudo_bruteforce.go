package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/helper"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

type SudoBruteForceRule struct {
	Threshold int
	Window    time.Duration
}

func NewSudoBruteForceRule() *SudoBruteForceRule {
	return &SudoBruteForceRule{
		Threshold: 5,
		Window:    2 * time.Minute,
	}
}

func (r *SudoBruteForceRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource: "auth",
		Program:   "sudo",
		EventTypes: []string{
			"SUDO_FAIL",
		},
	}
}

type sudoBruteState struct {
	failedByUser        map[string][]time.Time
	lastBruteForceAlert map[string]time.Time
	// cooldown fix fields
	lastAlertID  map[string]string
	runningCount map[string]int
}

func newSudoBruteState() *sudoBruteState {
	return &sudoBruteState{
		failedByUser:        make(map[string][]time.Time),
		lastBruteForceAlert: make(map[string]time.Time),
		lastAlertID:         make(map[string]string),
		runningCount:        make(map[string]int),
	}
}

// typed accessor — initialises on first call, no rule ever calls SetPrivate directly
func getSudoBruteState(ctx *context.DetectionContext) *sudoBruteState {
	if v, ok := ctx.GetPrivate("sudo_brute"); ok {
		return v.(*sudoBruteState)
	}
	s := newSudoBruteState()
	ctx.SetPrivate("sudo_brute", s)
	return s
}

func (r *SudoBruteForceRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {

	s := getSudoBruteState(ctx)
	user := event.Username
	now := event.Timestamp

	if user == "" {
		return nil
	}

	// initialize if needed
	if s.failedByUser[user] == nil {
		s.failedByUser[user] = []time.Time{}
	}

	// track failures
	for i := 0; i < event.EventCount; i++ {
		s.failedByUser[user] = append(s.failedByUser[user], now)
	}

	// prune old entries (sliding window)
	s.failedByUser[user] = helper.PruneOld(s.failedByUser[user], now, r.Window)

	if len(s.failedByUser[user]) < r.Threshold {
		return nil
	}

	last := s.lastBruteForceAlert[user]
	inCooldown := !last.IsZero() && now.Sub(last) <= r.Window

	if inCooldown {
		s.runningCount[user] += event.EventCount

		originalID := s.lastAlertID[user]
		if originalID != "" {
			updatedCount := len(s.failedByUser[user])
			return []*model.Alert{{
				IsUpdate:        true,
				OriginalAlertID: originalID,
				EventCount:      updatedCount,
			}}
		}
		return nil
	}

	totalCount := len(s.failedByUser[user])
	newAlert := model.NewAlert(
		"SUDO Brute Force",
		model.SeverityHigh,
		"privilege",
		fmt.Sprintf("Multiple failed sudo attempts by user %s", user),
		event,
		totalCount,
	)

	s.lastBruteForceAlert[user] = now
	s.lastAlertID[user] = newAlert.ID
	s.runningCount[user] = 0

	return []*model.Alert{newAlert}
}
