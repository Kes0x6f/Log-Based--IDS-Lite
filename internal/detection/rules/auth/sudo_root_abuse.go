package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/helper"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

type SudoRootAbuseRule struct {
	Threshold int
	Window    time.Duration
}

func NewSudoRootAbuseRule() *SudoRootAbuseRule {
	return &SudoRootAbuseRule{
		Threshold: 5,
		Window:    2 * time.Minute,
	}
}

func (r *SudoRootAbuseRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource: "auth",
		Program:   "sudo",
		EventTypes: []string{
			"SUDO_EXEC",
			"SUDO_SESSION_START",
		},
	}
}

func (r *SudoRootAbuseRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {
	fmt.Println("RULE RECEIVED:", event.Program, event.EventType)

	s := ctx.Sudo
	user := event.Username
	now := event.Timestamp

	switch event.EventType {

	// TRACK EXEC (identity anchor)
	case "SUDO_EXEC":
		fmt.Println("USER:", user)

		if user == "" {
			return nil
		}

		if s.LastExecByUser == nil {
			s.LastExecByUser = make(map[string][]time.Time)
		}

		s.LastExecByUser[user] = append(s.LastExecByUser[user], now)

		return nil

	// DETECT ROOT SESSION
	case "SUDO_SESSION_START":

		if s.RootSessionsByUser == nil {
			s.RootSessionsByUser = make(map[string][]time.Time)
		}

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
