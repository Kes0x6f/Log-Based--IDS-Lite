package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// AuditFileWriteRule fires when a process writes to a credential or critical
// system file watched with key="write_sensitive".
//
// Required auditd rules:
//
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F path=/etc/passwd   -F perm=w -k write_sensitive
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F path=/etc/shadow   -F perm=w -k write_sensitive
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F path=/etc/sudoers  -F perm=w -k write_sensitive
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F dir=/root/.ssh     -F perm=w -k write_sensitive
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F path=/etc/hosts    -F perm=w -k write_sensitive
//
// Writing to any of these paths is a CRITICAL event — it directly enables
// credential theft, privilege escalation, or persistence.
type AuditFileWriteRule struct {
	Cooldown time.Duration
}

func NewAuditFileWriteRule() *AuditFileWriteRule {
	return &AuditFileWriteRule{
		Cooldown: 5 * time.Minute,
	}
}

func (r *AuditFileWriteRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:  "audit",
		Program:    "auditd",
		EventTypes: []string{"FILE_WRITE"},
	}
}

// ── Private state ──────────────────────────────────────────────────────────

type auditFileWriteState struct {
	lastAlertByKey map[string]time.Time
	lastAlertID    map[string]string
}

func newAuditFileWriteState() *auditFileWriteState {
	return &auditFileWriteState{
		lastAlertByKey: make(map[string]time.Time),
		lastAlertID:    make(map[string]string),
	}
}

func getAuditFileWriteState(ctx *context.DetectionContext) *auditFileWriteState {
	if v, ok := ctx.GetPrivate("audit_file_write"); ok {
		return v.(*auditFileWriteState)
	}
	s := newAuditFileWriteState()
	ctx.SetPrivate("audit_file_write", s)
	return s
}

// ── Evaluate ───────────────────────────────────────────────────────────────

func (r *AuditFileWriteRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {
	s := getAuditFileWriteState(ctx)
	filePath := event.Command
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

	exeLabel := event.CallerExe
	if exeLabel == "" {
		exeLabel = "unknown"
	}

	alert := model.NewAlert(
		"Sensitive File Modified",
		model.SeverityCritical,
		"tampering",
		fmt.Sprintf("%s modified critical file %s (user: %s)", exeLabel, filePath, user),
		event,
		1,
	)

	s.lastAlertByKey[key] = now
	s.lastAlertID[key] = alert.ID

	return []*model.Alert{alert}
}
