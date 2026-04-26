package rule

import (
	"fmt"
	"strings"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// privilegedGroups maps group names whose membership confers root-equivalent access.
// docker is included because container escape trivially grants host root.
var privilegedGroups = map[string]bool{
	"sudo":   true,
	"wheel":  true,
	"root":   true,
	"admin":  true,
	"docker": true,
	"shadow": true,
	"adm":    true,
}

// GroupModifiedRule fires whenever a user is added to any group via usermod.
// Severity escalates to CRITICAL when the target group grants elevated privilege.
type GroupModifiedRule struct{}

func NewGroupModifiedRule() *GroupModifiedRule {
	return &GroupModifiedRule{}
}

func (r *GroupModifiedRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:  "auth",
		Program:    "usermod",
		EventTypes: []string{"GROUP_MODIFIED"},
	}
}

func (r *GroupModifiedRule) Evaluate(event *model.NormalizedEvent, _ *context.DetectionContext) []*model.Alert {
	if event.Username == "" {
		return nil
	}

	// event.Command holds the group name (set by UserModParser)
	group := event.Command

	severity := model.SeverityMedium
	if privilegedGroups[strings.ToLower(group)] {
		severity = model.SeverityCritical
	}

	msg := fmt.Sprintf("User %s added to group %s", event.Username, group)
	if severity == model.SeverityCritical {
		msg = fmt.Sprintf("User %s added to privileged group %s", event.Username, group)
	}

	return []*model.Alert{
		model.NewAlert(
			"Group Membership Changed",
			severity,
			"account",
			msg,
			event,
			1,
		),
	}
}
