package rule

import (
	"fmt"
	"strings"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/helper"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

type SudoCommandAbuseRule struct {
	Threshold int
	Window    time.Duration
}

func NewSudoCommandAbuseRule() *SudoCommandAbuseRule {
	return &SudoCommandAbuseRule{
		Threshold: 5,
		Window:    2 * time.Minute,
	}
}

func (r *SudoCommandAbuseRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource: "auth",
		Program:   "sudo",
		EventTypes: []string{
			"SUDO_EXEC",
		},
	}
}

type sudoCommandAbuseState struct {
	lastAbuseAlert map[string]time.Time
	// cooldown fix fields
	lastAlertID  map[string]string
	runningCount map[string]int
	recentCmds   map[string][]string
}

func newSudoCommandAbuseState() *sudoCommandAbuseState {
	return &sudoCommandAbuseState{
		lastAbuseAlert: make(map[string]time.Time),
		lastAlertID:    make(map[string]string),
		runningCount:   make(map[string]int),
		recentCmds:     make(map[string][]string),
	}
}

// typed accessor — initialises on first call, no rule ever calls SetPrivate directly
func getSudoCommandAbuseState(ctx *context.DetectionContext) *sudoCommandAbuseState {
	if v, ok := ctx.GetPrivate("sudo_command_abuse"); ok {
		return v.(*sudoCommandAbuseState)
	}
	s := newSudoCommandAbuseState()
	ctx.SetPrivate("sudo_command_abuse", s)
	return s
}

func (r *SudoCommandAbuseRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {

	s := getSudoCommandAbuseState(ctx)
	commandsByUser := ctx.SudoShared.CommandsByUser
	user := event.Username
	now := event.Timestamp

	if user == "" {
		return nil
	}

	// initialize map if needed
	if commandsByUser == nil {
		commandsByUser = make(map[string][]time.Time)
	}

	ctx.SudoShared.CommandsByUser[user] = append(ctx.SudoShared.CommandsByUser[user], now)
	ctx.SudoShared.CommandsByUser[user] = helper.PruneOld(ctx.SudoShared.CommandsByUser[user], now, r.Window)
	count := len(ctx.SudoShared.CommandsByUser[user])

	if event.Command != "" {
		s.recentCmds[user] = append(s.recentCmds[user], event.Command)
		if len(s.recentCmds[user]) > 5 {
			s.recentCmds[user] = s.recentCmds[user][len(s.recentCmds[user])-5:]
		}
	}

	if count < r.Threshold {
		return nil
	}

	last := s.lastAbuseAlert[user]
	inCooldown := !last.IsZero() && now.Sub(last) <= r.Window

	if inCooldown {
		originalID := s.lastAlertID[user]
		if originalID != "" {
			return []*model.Alert{{
				IsUpdate:        true,
				OriginalAlertID: originalID,
				EventCount:      count,
			}}
		}
		return nil
	}

	// Build command sample for ThreatDetail
	cmds := s.recentCmds[user]
	cmdSample := strings.Join(cmds, ",")

	// Truncate individual commands to keep ThreatDetail readable
	if len(cmdSample) > 120 {
		cmdSample = cmdSample[:117] + "..."
	}

	event.FailCount = count
	event.ThreatDetail = "cmds:" + cmdSample

	newAlert := model.NewAlert(
		"SUDO Command Abuse",
		model.SeverityHigh,
		"privilege",
		fmt.Sprintf("User %s executed %d sudo commands in %v", user, count, r.Window),
		event,
		count,
	)

	s.lastAbuseAlert[user] = now
	s.lastAlertID[user] = newAlert.ID
	s.runningCount[user] = 0

	return []*model.Alert{newAlert}
}
