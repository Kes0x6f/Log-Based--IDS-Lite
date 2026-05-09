package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/helper"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

type SudoSuccessAfterFailRule struct {
	Threshold int
	Window    time.Duration
}

func NewSudoSuccessAfterFailRule() *SudoSuccessAfterFailRule {
	return &SudoSuccessAfterFailRule{
		Threshold: 3,
		Window:    5 * time.Minute,
	}
}

func (r *SudoSuccessAfterFailRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:   "auth",
		Program:     "sudo",
		EventTypes:  []string{"SUDO_FAIL", "SUDO_SESSION_START", "SUDO_EXEC"},
		DisplayName: "SUDO Success After Failure",
		Description: "sudo succeeds immediately following repeated failures — possible password guessing success.",
		Defaults: detection.RuleDefaults{
			Threshold:   3,
			WindowSec:   300,
			CooldownSec: 300,
		},
	}
}

type sudoSuccessAfterFailState struct {
	lastExecByUser map[string][]time.Time
	lastAlert      map[string]time.Time
	lastAlertID    map[string]string
}

func newSudoSuccessAfterFailState() *sudoSuccessAfterFailState {
	return &sudoSuccessAfterFailState{
		lastExecByUser: make(map[string][]time.Time),
		lastAlert:      make(map[string]time.Time),
		lastAlertID:    make(map[string]string),
	}
}

func getSudoSuccessAfterFailState(ctx *context.DetectionContext) *sudoSuccessAfterFailState {
	if v, ok := ctx.GetPrivate("sudo_success_after_fail"); ok {
		return v.(*sudoSuccessAfterFailState)
	}
	s := newSudoSuccessAfterFailState()
	ctx.SetPrivate("sudo_success_after_fail", s)
	return s
}

func (r *SudoSuccessAfterFailRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext, cfg detection.ResolvedConfig) []*model.Alert {

	s := getSudoSuccessAfterFailState(ctx)
	recentFails := ctx.SudoShared.RecentFails
	user := event.Username
	now := event.Timestamp

	switch event.EventType {

	case "SUDO_FAIL":
		if user == "" {
			return nil
		}
		recentFails[user] = append(recentFails[user], now)
		recentFails[user] = helper.PruneOld(recentFails[user], now, cfg.Window)
		return nil

	case "SUDO_EXEC":
		if user == "" {
			return nil
		}
		s.lastExecByUser[user] = append(s.lastExecByUser[user], now)
		return nil

	case "SUDO_SESSION_START":
		for u, execTimes := range s.lastExecByUser {

			var remaining []time.Time

			for _, execTime := range execTimes {

				if now.Sub(execTime) <= 10*time.Second {

					// correlated user u — check if they had prior failures
					failCount := len(recentFails[u])

					if failCount >= cfg.Threshold {

						last := s.lastAlert[u]
						inCooldown := !last.IsZero() && now.Sub(last) <= cfg.Cooldown

						if inCooldown {
							if id := s.lastAlertID[u]; id != "" {
								return []*model.Alert{{
									IsUpdate:        true,
									OriginalAlertID: id,
									EventCount:      failCount,
								}}
							}
							return nil
						}

						alert := model.NewAlert(
							"SUDO Success After Failure",
							model.SeverityHigh,
							"privilege",
							fmt.Sprintf(
								"User %s succeeded with sudo after %d failed attempts",
								u,
								failCount,
							),
							event,
							failCount,
						)

						s.lastAlert[u] = now
						s.lastAlertID[u] = alert.ID

						// clear failures for this user — the session succeeded
						delete(recentFails, u)

						return []*model.Alert{alert}
					}

					// below threshold — still clear failures, session is clean
					delete(recentFails, u)

				} else {
					remaining = append(remaining, execTime)
				}
			}

			s.lastExecByUser[u] = remaining
		}
	}

	return nil
}
