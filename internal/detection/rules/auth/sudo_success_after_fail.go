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
		LogSource: "auth",
		Program:   "sudo",
		EventTypes: []string{
			"SUDO_FAIL",
			"SUDO_SESSION_START",
			"SUDO_EXEC",
		},
	}
}

func (r *SudoSuccessAfterFailRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {

	s := ctx.Sudo
	user := event.Username
	now := event.Timestamp

	if event.EventType != "SUDO_SESSION_START" && user == "" {
		return nil
	}
	switch event.EventType {

	// TRACK FAILURES
	case "SUDO_FAIL":

		if s.RecentFails[user] == nil {
			s.RecentFails[user] = []time.Time{}
		}

		s.RecentFails[user] = append(s.RecentFails[user], now)

		// prune old entries
		s.RecentFails[user] = helper.PruneOld(s.RecentFails[user], now, r.Window)

		return nil

	case "SUDO_EXEC":

		if user == "" {
			return nil
		}

		if s.LastExecByUser == nil {
			s.LastExecByUser = make(map[string][]time.Time)
		}

		s.LastExecByUser[user] = append(s.LastExecByUser[user], now)

		return nil

	// DETECT SUCCESS AFTER FAIL
	case "SUDO_SESSION_START":
		for u, execTimes := range s.LastExecByUser {

			var remaining []time.Time

			for _, execTime := range execTimes {

				if now.Sub(execTime) <= 10*time.Second {

					// ✅ MATCH FOUND

					if s.RootSessionsByUser[u] == nil {
						s.RootSessionsByUser[u] = []time.Time{}
					}

					s.RootSessionsByUser[u] = append(s.RootSessionsByUser[u], now)
					s.RootSessionsByUser[u] = helper.PruneOld(s.RootSessionsByUser[u], now, r.Window)

					count := len(s.RootSessionsByUser[u])

					if count >= r.Threshold {

						last := s.LastRootAlert[u]

						if last.IsZero() || now.Sub(last) > r.Window {

							alert := model.NewAlert(
								"SUDO Root Abuse",
								model.SeverityHigh,
								"privilege",
								fmt.Sprintf(
									"User %s escalated to root %d times within %v",
									u,
									count,
									r.Window,
								),
								event,
								count,
							)

							s.LastRootAlert[u] = now

							return []*model.Alert{alert}
						}
					}

				} else {
					// keep unmatched exec
					remaining = append(remaining, execTime)
				}
			}

			s.LastExecByUser[u] = remaining
		}
	}

	return nil
}
