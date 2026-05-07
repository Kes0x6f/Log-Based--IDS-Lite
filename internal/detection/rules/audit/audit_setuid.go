package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// AuditSetuidRule fires when a binary has its setuid bit set via chmod/fchmod.
//
// Why it matters:
//   - A setuid binary runs as its owner (usually root) regardless of who
//     executes it. Creating one is a trivial privilege escalation backdoor.
//   - Legitimate setuid binaries are installed by the package manager and
//     never need their bit set manually. Any manual chmod +s is suspicious.
//
// The parser filters for actual setuid-bit presence (mode & 04000 != 0)
// so this rule only fires on genuinely setuid chmod calls.
//
// Required auditd rules:
//
//	-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -k setuid_binary
//
// A per-(user, binary) cooldown prevents repeated alerts when something
// retries the chmod in a loop.  The key is composite (user:path) so that
// two different users setting the setuid bit on the same binary each
// generate their own independent alert and cooldown window.
type AuditSetuidRule struct {
	Cooldown time.Duration
}

func NewAuditSetuidRule() *AuditSetuidRule {
	return &AuditSetuidRule{
		Cooldown: 15 * time.Minute,
	}
}

func (r *AuditSetuidRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:  "audit",
		Program:    "auditd",
		EventTypes: []string{"SETUID"},
	}
}

// ── Private state ──────────────────────────────────────────────────────────

type auditSetuidState struct {
	// FIX: key is now "user:binPath" instead of bare "binPath".
	// Using only binPath meant two different users chmod-ing the setuid bit
	// on two different binaries would incorrectly share the same cooldown entry
	// and could suppress each other's alerts.
	lastAlertByKey map[string]time.Time
	lastAlertID    map[string]string
}

func newAuditSetuidState() *auditSetuidState {
	return &auditSetuidState{
		lastAlertByKey: make(map[string]time.Time),
		lastAlertID:    make(map[string]string),
	}
}

func getAuditSetuidState(ctx *context.DetectionContext) *auditSetuidState {
	if v, ok := ctx.GetPrivate("audit_setuid"); ok {
		return v.(*auditSetuidState)
	}
	s := newAuditSetuidState()
	ctx.SetPrivate("audit_setuid", s)
	return s
}

// ── Evaluate ───────────────────────────────────────────────────────────────

func (r *AuditSetuidRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {
	s := getAuditSetuidState(ctx)
	binPath := event.Command // name= from PATH record (verified setuid by parser)
	user := event.Username
	now := event.Timestamp

	if binPath == "" {
		return nil
	}

	// FIX: composite key so each (user, binary) pair has its own cooldown.
	// Previously the key was just binPath, which caused user A chmod-ing
	// /usr/local/bin/evil to suppress alerts for user B chmod-ing the same path.
	key := user + ":" + binPath

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

	event.ThreatDetail = "bit:setuid"

	exeLabel := event.CallerExe
	if exeLabel == "" {
		exeLabel = "unknown"
	}

	alert := model.NewAlert(
		"Setuid Bit Set on Binary",
		model.SeverityCritical,
		"privilege-escalation",
		fmt.Sprintf("Setuid bit set on %s by %s (user: %s)", binPath, exeLabel, user),
		event,
		1,
	)

	s.lastAlertByKey[key] = now
	s.lastAlertID[key] = alert.ID

	return []*model.Alert{alert}
}
