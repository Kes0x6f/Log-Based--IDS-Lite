package rule

import (
	"fmt"
	"strings"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
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
func calculateRisk(cmd string, user string, shared *context.SharedSudoContext) int {

	score := -1
	baseCmd := extractBaseCommand(cmd)

	for _, c := range sensitiveCommands {
		patternIsMultiWord := strings.Contains(c.Pattern, " ")
		if (!patternIsMultiWord && baseCmd == c.Pattern) ||
			(patternIsMultiWord && strings.Contains(cmd, c.Pattern)) {
			score = c.Score
			break
		}
	}

	// If command not sensitive, ignore completely
	if score == -1 {
		return 0
	}

	// Behavior Context
	failures := len(shared.RecentFails[user])
	if failures >= 3 {
		score += 20
	}

	//  Frequency Context
	execCount := len(shared.CommandsByUser[user])
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

	if cmd == "" || user == "" {
		return nil
	}

	if ctx.SudoShared.CommandsByUser == nil {
		ctx.SudoShared.CommandsByUser = make(map[string][]time.Time)
	}

	// Track command frequency
	if ctx.SudoShared.CommandsByUser[user] == nil {
		ctx.SudoShared.CommandsByUser[user] = []time.Time{}
	}
	cmd = strings.ToLower(strings.TrimSpace(cmd))
	score := calculateRisk(cmd, user, ctx.SudoShared)

	if score == 0 {
		return nil
	}

	severity := mapSeverity(score)

	reason := "base-score"
	if len(ctx.SudoShared.RecentFails[user]) >= 3 {
		reason = "prior-failures"
	} else if len(ctx.SudoShared.CommandsByUser[user]) >= 5 {
		reason = "high-frequency"
	}

	event.ThreatDetail = fmt.Sprintf("score:%d reason:%s", score, reason)

	alert := model.NewAlert(
		"SUDO Sensitive Command Execution",
		severity,
		"privilege",
		fmt.Sprintf("User %s executed sensitive command: %s (risk score: %d)", user, cmd, score),
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
