package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// AuditCapsetRule fires when a process modifies its own Linux capability set
// via the capset syscall.
//
// Why it matters:
//   - Linux capabilities divide root's privileges into discrete units
//     (CAP_NET_ADMIN, CAP_SYS_PTRACE, CAP_DAC_OVERRIDE, etc.).
//   - A process calling capset to elevate its own capabilities is a privilege
//     escalation technique that bypasses the need for a full root shell.
//   - Legitimate programs that need elevated capabilities have them set at
//     install time (via setcap / file capabilities) and never call capset
//     dynamically at runtime.
//
// Required auditd rules:
//
//	-a always,exit -F arch=b64 -S capset -k capset
type AuditCapsetRule struct {
	Cooldown time.Duration
}

func NewAuditCapsetRule() *AuditCapsetRule {
	return &AuditCapsetRule{
		Cooldown: 10 * time.Minute,
	}
}

func (r *AuditCapsetRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:  "audit",
		Program:    "auditd",
		EventTypes: []string{"CAPSET"},
	}
}

// ── Private state ──────────────────────────────────────────────────────────

type auditCapsetState struct {
	lastAlertByKey map[string]time.Time
	lastAlertID    map[string]string
	countByKey     map[string]int
}

func newAuditCapsetState() *auditCapsetState {
	return &auditCapsetState{
		lastAlertByKey: make(map[string]time.Time),
		lastAlertID:    make(map[string]string),
		countByKey:     make(map[string]int),
	}
}

func getAuditCapsetState(ctx *context.DetectionContext) *auditCapsetState {
	if v, ok := ctx.GetPrivate("audit_capset"); ok {
		return v.(*auditCapsetState)
	}
	s := newAuditCapsetState()
	ctx.SetPrivate("audit_capset", s)
	return s
}

// ── Evaluate ───────────────────────────────────────────────────────────────

func (r *AuditCapsetRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {
	s := getAuditCapsetState(ctx)
	exe := event.Command
	user := event.Username
	now := event.Timestamp

	if exe == "" {
		exe = "unknown"
	}

	key := user + ":" + exe
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

	alert := model.NewAlert(
		"Capability Change Detected",
		model.SeverityHigh,
		"privilege-escalation",
		fmt.Sprintf(
			"Process %s (user: %s) called capset — unexpected runtime capability change",
			exe, user,
		),
		event,
		count,
	)

	s.lastAlertByKey[key] = now
	s.lastAlertID[key] = alert.ID

	return []*model.Alert{alert}
}
