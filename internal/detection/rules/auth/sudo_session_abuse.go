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

type sudoSessionAbuseState struct {
	lastExecByUser      map[string][]time.Time
	sessionStartsByUser map[string][]time.Time
	lastSessionAlert    map[string]time.Time
	lastAlertID         map[string]string
	runningCount        map[string]int
}

func newSudoSessionAbuseState() *sudoSessionAbuseState {
	return &sudoSessionAbuseState{
		lastExecByUser:      make(map[string][]time.Time),
		sessionStartsByUser: make(map[string][]time.Time),
		lastSessionAlert:    make(map[string]time.Time),
		lastAlertID:         make(map[string]string),
		runningCount:        make(map[string]int),
	}
}

func getSudoSessionAbuseState(ctx *context.DetectionContext) *sudoSessionAbuseState {
	if v, ok := ctx.GetPrivate("sudo_session_abuse"); ok {
		return v.(*sudoSessionAbuseState)
	}
	s := newSudoSessionAbuseState()
	ctx.SetPrivate("sudo_session_abuse", s)
	return s
}

func (r *SudoSessionAbuseRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {

	s := getSudoSessionAbuseState(ctx)
	now := event.Timestamp

	switch event.EventType {

	case "SUDO_EXEC":
		user := event.Username
		if user == "" {
			return nil
		}
		s.lastExecByUser[user] = append(s.lastExecByUser[user], now)
		return nil

	case "SUDO_SESSION_START":
		for u, execTimes := range s.lastExecByUser {

			var remainingExecs []time.Time

			for _, execTime := range execTimes {

				if now.Sub(execTime) <= 100*time.Second {

					s.sessionStartsByUser[u] = append(s.sessionStartsByUser[u], now)
					s.sessionStartsByUser[u] = helper.PruneOld(s.sessionStartsByUser[u], now, r.Window)

					count := len(s.sessionStartsByUser[u])

					if count >= r.Threshold {

						last := s.lastSessionAlert[u]
						inCooldown := !last.IsZero() && now.Sub(last) <= r.Window

						if inCooldown {
							if id := s.lastAlertID[u]; id != "" {
								return []*model.Alert{{
									IsUpdate:        true,
									OriginalAlertID: id,
									EventCount:      count,
								}}
							}
							return nil
						}

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

						s.lastSessionAlert[u] = now
						s.lastAlertID[u] = alert.ID

						return []*model.Alert{alert}
					}

				} else {
					remainingExecs = append(remainingExecs, execTime)
				}
			}

			s.lastExecByUser[u] = remainingExecs
		}
	}

	return nil
}
