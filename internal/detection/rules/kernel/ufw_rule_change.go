package rule

import (
	"fmt"
	"strings"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// UFWRuleChangeRule fires whenever a UFW configuration file is modified.
//
// Why it matters:
//   - Modifying /etc/ufw/user.rules or user6.rules directly (or via the ufw
//     command) changes what traffic the firewall allows or blocks.
//   - Attackers commonly weaken the firewall after gaining root to open a
//     reverse-shell port or permit exfiltration.
//   - Legitimate admins make infrequent, intentional changes — any surprise
//     modification warrants review.
//
// Severity:
//   - CRITICAL when the file path suggests a rule *deletion* or a blanket
//     allow (file names contain "before" or the path is user.rules/user6.rules).
//   - HIGH for all other UFW config writes.
//
// Required auditd rules (/etc/audit/rules.d/ids.rules):
//
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F path=/etc/ufw/user.rules  -F perm=w -k ufw_change
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F path=/etc/ufw/user6.rules -F perm=w -k ufw_change
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F dir=/etc/ufw              -F perm=w -k ufw_change
type UFWRuleChangeRule struct {
	Cooldown time.Duration
}

func NewUFWRuleChangeRule() *UFWRuleChangeRule {
	return &UFWRuleChangeRule{
		Cooldown: 5 * time.Minute,
	}
}

func (r *UFWRuleChangeRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:  "audit",
		Program:    "auditd",
		EventTypes: []string{"UFW_RULE_CHANGE"},
	}
}

// ── Private state ──────────────────────────────────────────────────────────

type ufwRuleChangeState struct {
	lastAlertByKey map[string]time.Time
	lastAlertID    map[string]string
	countByKey     map[string]int
}

func newUFWRuleChangeState() *ufwRuleChangeState {
	return &ufwRuleChangeState{
		lastAlertByKey: make(map[string]time.Time),
		lastAlertID:    make(map[string]string),
		countByKey:     make(map[string]int),
	}
}

func getUFWRuleChangeState(ctx *context.DetectionContext) *ufwRuleChangeState {
	if v, ok := ctx.GetPrivate("ufw_rule_change"); ok {
		return v.(*ufwRuleChangeState)
	}
	s := newUFWRuleChangeState()
	ctx.SetPrivate("ufw_rule_change", s)
	return s
}

// ── Evaluate ───────────────────────────────────────────────────────────────

func (r *UFWRuleChangeRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {
	s := getUFWRuleChangeState(ctx)
	filePath := event.Command // name= from audit PATH record
	user := event.Username
	now := event.Timestamp

	if filePath == "" {
		return nil
	}

	// CRITICAL for the primary rule files; HIGH for anything else under /etc/ufw.
	severity := model.SeverityHigh
	if strings.Contains(filePath, "user.rules") || strings.Contains(filePath, "user6.rules") {
		severity = model.SeverityCritical
	}

	key := user + ":" + filePath
	s.countByKey[key]++
	count := s.countByKey[key]

	last := s.lastAlertByKey[key]
	inCooldown := !last.IsZero() && now.Sub(last) <= r.Cooldown
	if inCooldown {
		if id := s.lastAlertID[key]; id != "" {
			return []*model.Alert{{
				IsUpdate:        true,
				OriginalAlertID: id,
				EventCount:      count,
			}}
		}
		return nil
	}

	s.countByKey[key] = 1

	msg := fmt.Sprintf(
		"UFW firewall rule file modified: %s (user: %s) — verify this change was intentional",
		filePath, user,
	)

	alert := model.NewAlert(
		"UFW Firewall Rule Changed",
		severity,
		"firewall",
		msg,
		event,
		count,
	)

	s.lastAlertByKey[key] = now
	s.lastAlertID[key] = alert.ID

	return []*model.Alert{alert}
}
