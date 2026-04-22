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

type sudoRootAbuseState struct {
	lastExecByUser     map[string][]time.Time
	rootSessionsByUser map[string][]time.Time
	lastRootAlert      map[string]time.Time
	lastAlertID        map[string]string
	runningCount       map[string]int
}

func newSudoRootAbuseState() *sudoRootAbuseState {
	return &sudoRootAbuseState{
		lastExecByUser:     make(map[string][]time.Time),
		rootSessionsByUser: make(map[string][]time.Time),
		lastRootAlert:      make(map[string]time.Time),
		lastAlertID:        make(map[string]string),
		runningCount:       make(map[string]int),
	}
}

func getSudoRootAbuseState(ctx *context.DetectionContext) *sudoRootAbuseState {
	if v, ok := ctx.GetPrivate("sudo_root_abuse"); ok {
		return v.(*sudoRootAbuseState)
	}
	s := newSudoRootAbuseState()
	ctx.SetPrivate("sudo_root_abuse", s)
	return s
}

func (r *SudoRootAbuseRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {

	s := getSudoRootAbuseState(ctx)
	user := event.Username
	now := event.Timestamp

	switch event.EventType {

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

					if s.rootSessionsByUser[u] == nil {
						s.rootSessionsByUser[u] = []time.Time{}
					}

					s.rootSessionsByUser[u] = append(s.rootSessionsByUser[u], now)
					s.rootSessionsByUser[u] = helper.PruneOld(s.rootSessionsByUser[u], now, r.Window)

					count := len(s.rootSessionsByUser[u])

					if count >= r.Threshold {

						last := s.lastRootAlert[u]
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

						s.lastRootAlert[u] = now
						s.lastAlertID[u] = alert.ID

						return []*model.Alert{alert}
					}

				} else {
					remaining = append(remaining, execTime)
				}
			}

			s.lastExecByUser[u] = remaining
		}
	}

	return nil
}
