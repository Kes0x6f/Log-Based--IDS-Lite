package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/helper"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// SuSuccessAfterFailRule detects a successful su immediately following
// N or more failed attempts within a time window — a strong brute-force signal.
type SuSuccessAfterFailRule struct {
	Threshold int
	Window    time.Duration
}

func NewSuSuccessAfterFailRule() *SuSuccessAfterFailRule {
	return &SuSuccessAfterFailRule{
		Threshold: 3,
		Window:    5 * time.Minute,
	}
}

func (r *SuSuccessAfterFailRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:  "auth",
		Program:    "su",
		EventTypes: []string{"SU_FAIL", "SU_SUCCESS"},
	}
}

type suSuccessAfterFailState struct {
	recentFailures  map[string][]time.Time // keyed by username
	lastAlertByUser map[string]time.Time
	lastAlertID     map[string]string
}

func newSuSuccessAfterFailState() *suSuccessAfterFailState {
	return &suSuccessAfterFailState{
		recentFailures:  make(map[string][]time.Time),
		lastAlertByUser: make(map[string]time.Time),
		lastAlertID:     make(map[string]string),
	}
}

func getSuSuccessAfterFailState(ctx *context.DetectionContext) *suSuccessAfterFailState {
	if v, ok := ctx.GetPrivate("su_success_after_fail"); ok {
		return v.(*suSuccessAfterFailState)
	}
	s := newSuSuccessAfterFailState()
	ctx.SetPrivate("su_success_after_fail", s)
	return s
}

func (r *SuSuccessAfterFailRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {
	s := getSuSuccessAfterFailState(ctx)
	user := event.Username
	now := event.Timestamp

	if user == "" {
		return nil
	}

	switch event.EventType {

	case "SU_FAIL":
		s.recentFailures[user] = append(s.recentFailures[user], now)
		s.recentFailures[user] = helper.PruneOld(s.recentFailures[user], now, r.Window)
		return nil

	case "SU_SUCCESS":
		failures := s.recentFailures[user]

		if len(failures) >= r.Threshold {
			last := s.lastAlertByUser[user]

			if now.Sub(last) > r.Window {
				alert := model.NewAlert(
					"SU Success After Failure",
					model.SeverityCritical,
					"privilege",
					fmt.Sprintf(
						"su succeeded for user %s after %d failed attempt(s)",
						user,
						len(failures),
					),
					event,
					len(failures),
				)

				s.lastAlertByUser[user] = now
				s.lastAlertID[user] = alert.ID
				delete(s.recentFailures, user)

				return []*model.Alert{alert}
			}
		}

		// Clean state regardless — successful su resets the failure window
		delete(s.recentFailures, user)
	}

	return nil
}
