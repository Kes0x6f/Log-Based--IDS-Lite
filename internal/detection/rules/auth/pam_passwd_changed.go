package rule

import (
	"fmt"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// privilegedAccounts maps account names that receive elevated severity on password change.
var privilegedAccounts = map[string]bool{
	"root":   true,
	"daemon": true,
	"nobody": true,
}

// PasswdChangedRule fires on every password change.
// Severity is CRITICAL for privileged accounts (root, daemon), MEDIUM for regular users.
type PasswdChangedRule struct{}

func NewPasswdChangedRule() *PasswdChangedRule {
	return &PasswdChangedRule{}
}

func (r *PasswdChangedRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:  "auth",
		Program:    "passwd",
		EventTypes: []string{"PASSWD_CHANGED"},
	}
}

func (r *PasswdChangedRule) Evaluate(event *model.NormalizedEvent, _ *context.DetectionContext) []*model.Alert {
	if event.Username == "" {
		return nil
	}

	severity := model.SeverityMedium
	if privilegedAccounts[event.Username] {
		severity = model.SeverityCritical
	}

	privilegedFlag := "no"
	if privilegedAccounts[event.Username] {
		privilegedFlag = "yes"
	}
	event.ThreatDetail = fmt.Sprintf("account:%s privileged:%s", event.Username, privilegedFlag)

	return []*model.Alert{
		model.NewAlert(
			"Password Changed",
			severity,
			"account",
			fmt.Sprintf("Password changed for user: %s", event.Username),
			event,
			1,
		),
	}
}
