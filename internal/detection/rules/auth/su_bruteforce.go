package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/helper"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// SuBruteForceRule detects repeated failed su attempts by the same user
// within a sliding time window.
type SuBruteForceRule struct {
	Threshold int
	Window    time.Duration
}

func NewSuBruteForceRule() *SuBruteForceRule {
	return &SuBruteForceRule{
		Threshold: 5,
		Window:    2 * time.Minute,
	}
}

func (r *SuBruteForceRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:  "auth",
		Program:    "su",
		EventTypes: []string{"SU_FAIL"},
	}
}

type suBruteState struct {
	failedByUser    map[string][]time.Time
	lastAlertByUser map[string]time.Time
	lastAlertID     map[string]string
	runningCount    map[string]int
}

func newSuBruteState() *suBruteState {
	return &suBruteState{
		failedByUser:    make(map[string][]time.Time),
		lastAlertByUser: make(map[string]time.Time),
		lastAlertID:     make(map[string]string),
		runningCount:    make(map[string]int),
	}
}

func getSuBruteState(ctx *context.DetectionContext) *suBruteState {
	if v, ok := ctx.GetPrivate("su_brute"); ok {
		return v.(*suBruteState)
	}
	s := newSuBruteState()
	ctx.SetPrivate("su_brute", s)
	return s
}

func (r *SuBruteForceRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {
	s := getSuBruteState(ctx)
	user := event.Username
	now := event.Timestamp

	if user == "" {
		return nil
	}

	for i := 0; i < event.EventCount; i++ {
		s.failedByUser[user] = append(s.failedByUser[user], now)
	}
	s.failedByUser[user] = helper.PruneOld(s.failedByUser[user], now, r.Window)

	if len(s.failedByUser[user]) < r.Threshold {
		return nil
	}

	last := s.lastAlertByUser[user]
	inCooldown := !last.IsZero() && now.Sub(last) <= r.Window

	if inCooldown {
		if id := s.lastAlertID[user]; id != "" {
			return []*model.Alert{{
				IsUpdate:        true,
				OriginalAlertID: id,
				EventCount:      len(s.failedByUser[user]),
			}}
		}
		return nil
	}

	totalCount := len(s.failedByUser[user])
	targetAcct := event.Command
	if targetAcct == "" {
		targetAcct = "unknown"
	}
	event.FailCount = totalCount
	event.TargetUser = targetAcct
	newAlert := model.NewAlert(
		"SU Brute Force",
		model.SeverityHigh,
		"privilege",
		fmt.Sprintf("SU brute force by user %s targeting %s: %d failures in %v", user, targetAcct, totalCount, r.Window),
		event,
		totalCount,
	)

	s.lastAlertByUser[user] = now
	s.lastAlertID[user] = newAlert.ID
	s.runningCount[user] = 0

	return []*model.Alert{newAlert}
}
