package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/helper"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

type SudoSessionAbuseRule struct {
	Threshold int
	Window    time.Duration
}

func NewSudoSessionAbuseRule() *SudoSessionAbuseRule {
	return &SudoSessionAbuseRule{
		Threshold: 4,
		Window:    2 * time.Minute,
	}
}

func (r *SudoSessionAbuseRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource: "auth",
		Program:   "sudo",
		EventTypes: []string{
			"SUDO_EXEC",
			"SUDO_SESSION_START",
		},
	}
}

func (r *SudoSessionAbuseRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {

	s := ctx.Sudo
	now := event.Timestamp

	switch event.EventType {

	// TRACK EXEC
	case "SUDO_EXEC":

		user := event.Username
		if user == "" {
			return nil
		}

		if s.LastExecByUser == nil {
			s.LastExecByUser = make(map[string][]time.Time)
		}

		s.LastExecByUser[user] = append(s.LastExecByUser[user], now)

		return nil

	// DETECT SESSION ABUSE
	case "SUDO_SESSION_START":

		if s.SessionStartsByUser == nil {
			s.SessionStartsByUser = make(map[string][]time.Time)
		}

		for u, execTimes := range s.LastExecByUser {

			var remainingExecs []time.Time

			for _, execTime := range execTimes {

				if now.Sub(execTime) <= 5*time.Second {

					// correlate → session start belongs to user u

					s.SessionStartsByUser[u] = append(s.SessionStartsByUser[u], now)
					s.SessionStartsByUser[u] = helper.PruneOld(s.SessionStartsByUser[u], now, r.Window)

					count := len(s.SessionStartsByUser[u])

					if count >= r.Threshold {

						last := s.LastSessionAlert[u]

						if last.IsZero() || now.Sub(last) > r.Window {

							alert := model.NewAlert(
								"SUDO Session Abuse",
								model.SeverityMedium,
								"privilege",
								fmt.Sprintf(
									"User %s opened %d sudo sessions within %v",
									u,
									count,
									r.Window,
								),
								event,
								count,
							)

							s.LastSessionAlert[u] = now

							return []*model.Alert{alert}
						}
					}

				} else {
					remainingExecs = append(remainingExecs, execTime)
				}
			}

			s.LastExecByUser[u] = remainingExecs
		}
	}

	return nil
}
