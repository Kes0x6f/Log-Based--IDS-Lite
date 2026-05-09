package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// AuditPtraceRule fires when a process uses the ptrace syscall.
//
// Why it matters:
//   - ptrace is the mechanism behind gdb, strace, and ltrace — all legitimate
//     debugging tools. However, it is also the primary technique used to:
//     · Inject shellcode into a running process (classic shellcode injection)
//     · Dump process memory to extract credentials or keys
//     · Hook function calls (e.g. to intercept SSH passwords in sshd memory)
//   - In production, ptrace on a live service process is almost always malicious.
//
// A per-binary cooldown prevents alert floods from debuggers run repeatedly
// while still alerting on the first occurrence per session.
//
// Required auditd rules:
//
//	-a always,exit -F arch=b64 -S ptrace -k ptrace
type AuditPtraceRule struct {
	Cooldown time.Duration
}

func NewAuditPtraceRule() *AuditPtraceRule {
	return &AuditPtraceRule{
		Cooldown: 10 * time.Minute,
	}
}

func (r *AuditPtraceRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:   "audit",
		Program:     "auditd",
		EventTypes:  []string{"PTRACE"},
		DisplayName: "Ptrace Syscall Detected",
		Description: "Process calls ptrace — memory injection, credential dumping, or function hooking.",
		Defaults: detection.RuleDefaults{
			Threshold:   0,
			WindowSec:   0,
			CooldownSec: 600,
		},
	}
}

// ── Private state ──────────────────────────────────────────────────────────

// key = "user:exe" — the same binary run by the same user in a loop
type auditPtraceState struct {
	lastAlertByKey map[string]time.Time
	lastAlertID    map[string]string
	countByKey     map[string]int
}

func newAuditPtraceState() *auditPtraceState {
	return &auditPtraceState{
		lastAlertByKey: make(map[string]time.Time),
		lastAlertID:    make(map[string]string),
		countByKey:     make(map[string]int),
	}
}

func getAuditPtraceState(ctx *context.DetectionContext) *auditPtraceState {
	if v, ok := ctx.GetPrivate("audit_ptrace"); ok {
		return v.(*auditPtraceState)
	}
	s := newAuditPtraceState()
	ctx.SetPrivate("audit_ptrace", s)
	return s
}

// ── Evaluate ───────────────────────────────────────────────────────────────

func (r *AuditPtraceRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext, cfg detection.ResolvedConfig) []*model.Alert {
	s := getAuditPtraceState(ctx)
	exe := event.Command // the binary calling ptrace
	user := event.Username
	now := event.Timestamp

	if exe == "" {
		exe = "unknown"
	}

	key := user + ":" + exe
	s.countByKey[key]++
	count := s.countByKey[key]

	last := s.lastAlertByKey[key]
	inCooldown := !last.IsZero() && now.Sub(last) <= cfg.Cooldown
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

	event.ThreatDetail = fmt.Sprintf("caller:%s", exe)

	alert := model.NewAlert(
		"Ptrace Syscall Detected",
		model.SeverityCritical,
		"exploitation",
		fmt.Sprintf("%s called ptrace (user: %s) — possible memory injection or credential dumping",
			exe, user),
		event,
		count,
	)

	s.lastAlertByKey[key] = now
	s.lastAlertID[key] = alert.ID

	return []*model.Alert{alert}
}
