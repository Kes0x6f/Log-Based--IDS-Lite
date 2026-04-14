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

type SudoSensitiveCommandRule struct{}

func NewSudoSensitiveCommandRule() *SudoSensitiveCommandRule {
	return &SudoSensitiveCommandRule{}
}

type CommandRisk struct {
	Pattern string
	Score   int
}

var sensitiveCommands = []CommandRisk{
	{"rm -rf", 100},
	{"mkfs", 95},
	{"dd", 90},
	{"chmod 777", 70},
	{"useradd", 60},
	{"passwd", 50},
}

func (r *SudoSensitiveCommandRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource: "auth",
		Program:   "sudo",
		EventTypes: []string{
			"SUDO_EXEC",
		},
	}
}
func calculateRisk(cmd string, user string, ctx *context.DetectionContext) int {

	score := -1
	baseCmd := extractBaseCommand(cmd)

	for _, c := range sensitiveCommands {
		if baseCmd == c.Pattern || strings.HasPrefix(cmd, c.Pattern) {
			score = c.Score
			break
		}
	}

	// If command not sensitive, ignore completely
	if score == -1 {
		return 0
	}

	// Behavior Context
	failures := len(ctx.Sudo.RecentFails[user])
	if failures >= 3 {
		score += 20
	}

	//  Frequency Context
	execCount := len(ctx.Sudo.CommandsByUser[user])
	if execCount >= 5 {
		score += 10
	}

	return score
}

func mapSeverity(score int) model.Severity {

	switch {
	case score >= 100:
		return model.SeverityCritical
	case score >= 70:
		return model.SeverityHigh
	case score >= 40:
		return model.SeverityMedium
	default:
		return model.SeverityLow
	}
}

func (r *SudoSensitiveCommandRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {

	cmd := event.Command
	user := event.Username
	now := event.Timestamp

	if cmd == "" || user == "" {
		return nil
	}

	if ctx.Sudo.CommandsByUser == nil {
		ctx.Sudo.CommandsByUser = make(map[string][]time.Time)
	}

	// Track command frequency
	if ctx.Sudo.CommandsByUser[user] == nil {
		ctx.Sudo.CommandsByUser[user] = []time.Time{}
	}

	ctx.Sudo.CommandsByUser[user] = append(ctx.Sudo.CommandsByUser[user], now)
	ctx.Sudo.CommandsByUser[user] = helper.PruneOld(ctx.Sudo.CommandsByUser[user], now, 5*time.Minute)

	// Calculate risk
	cmd = strings.ToLower(strings.TrimSpace(cmd))
	score := calculateRisk(cmd, user, ctx)

	if score == 0 {
		return nil
	}

	severity := mapSeverity(score)

	alert := model.NewAlert(
		"SUDO Sensitive Command Execution",
		severity,
		"privilege",
		fmt.Sprintf(
			"User %s executed sensitive command: %s",
			user,
			cmd,
		),
		event,
		1,
	)

	return []*model.Alert{alert}
}

func extractBaseCommand(cmd string) string {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return ""
	}

	// get last part of path
	base := parts[0]
	if strings.Contains(base, "/") {
		split := strings.Split(base, "/")
		return split[len(split)-1]
	}

	return base
}
