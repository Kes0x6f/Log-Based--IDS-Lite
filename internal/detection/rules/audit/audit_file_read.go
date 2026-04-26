package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// AuditFileReadRule fires when a process reads a file watched by the auditd
// rule with key="read_sensitive".
//
// Required auditd rules (/etc/audit/rules.d/ids.rules):
//
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F path=/etc/shadow         -F perm=r -k read_sensitive
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F path=/etc/gshadow        -F perm=r -k read_sensitive
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F path=/etc/sudoers        -F perm=r -k read_sensitive
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F path=/etc/sudoers.d      -F perm=r -k read_sensitive
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F path=/root/.ssh/authorized_keys -F perm=r -k read_sensitive
//
// A per-(file, user) cooldown prevents floods from processes that re-open the
// same file in a tight loop (e.g. a PAM module checking /etc/shadow on every
// auth attempt) while still alerting on the first access.
type AuditFileReadRule struct {
	Cooldown time.Duration
}

func NewAuditFileReadRule() *AuditFileReadRule {
	return &AuditFileReadRule{
		Cooldown: 5 * time.Minute,
	}
}

func (r *AuditFileReadRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:  "audit",
		Program:    "auditd",
		EventTypes: []string{"FILE_READ"},
	}
}

// ── Private state ──────────────────────────────────────────────────────────

type auditFileReadState struct {
	lastAlertByKey map[string]time.Time // "user:filepath"
	lastAlertID    map[string]string
}

func newAuditFileReadState() *auditFileReadState {
	return &auditFileReadState{
		lastAlertByKey: make(map[string]time.Time),
		lastAlertID:    make(map[string]string),
	}
}

func getAuditFileReadState(ctx *context.DetectionContext) *auditFileReadState {
	if v, ok := ctx.GetPrivate("audit_file_read"); ok {
		return v.(*auditFileReadState)
	}
	s := newAuditFileReadState()
	ctx.SetPrivate("audit_file_read", s)
	return s
}

// ── Evaluate ───────────────────────────────────────────────────────────────

func (r *AuditFileReadRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {
	s := getAuditFileReadState(ctx)
	filePath := event.Command // name= from PATH record
	user := event.Username
	now := event.Timestamp

	if filePath == "" {
		return nil
	}

	key := user + ":" + filePath
	last := s.lastAlertByKey[key]
	inCooldown := !last.IsZero() && now.Sub(last) <= r.Cooldown

	if inCooldown {
		if id := s.lastAlertID[key]; id != "" {
			return []*model.Alert{{
				IsUpdate:        true,
				OriginalAlertID: id,
				EventCount:      1,
			}}
		}
		return nil
	}

	alert := model.NewAlert(
		"Sensitive File Read",
		model.SeverityHigh,
		"credential-access",
		fmt.Sprintf("Sensitive file read: %s (user: %s)", filePath, user),
		event,
		1,
	)

	s.lastAlertByKey[key] = now
	s.lastAlertID[key] = alert.ID

	return []*model.Alert{alert}
}
