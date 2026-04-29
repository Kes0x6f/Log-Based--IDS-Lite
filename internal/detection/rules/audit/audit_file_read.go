package rule

import (
	"fmt"
	"strings"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// trustedReaders maps file paths to the set of binaries that legitimately
// open them as part of normal system operation.
//
// The threat model here is: a rogue process (attacker script, malware, leaked
// shell) reading credential files. System daemons doing so as part of their
// normal auth / policy-check flow are expected and should not alert.
//
// To find what is legitimately reading a file on your system run:
//
//	sudo ausearch -k read_sensitive | grep exe= | sort -u
var trustedReaders = map[string]map[string]bool{
	"/etc/shadow": {
		"/usr/sbin/sshd":        true, // PAM auth
		"/usr/bin/login":        true, // console login
		"/usr/bin/sudo":         true, // PAM auth for sudo
		"/usr/sbin/sudo":        true,
		"/usr/bin/su":           true,
		"/usr/sbin/su":          true,
		"/usr/bin/passwd":       true, // password change
		"/usr/sbin/unix_chkpwd": true, // PAM helper
		"/sbin/unix_chkpwd":     true,
	},
	"/etc/gshadow": {
		"/usr/sbin/sshd":  true,
		"/usr/bin/sudo":   true,
		"/usr/sbin/sudo":  true,
		"/usr/bin/passwd": true,
		"/usr/bin/newgrp": true,
	},
	"/etc/sudoers": {
		"/usr/bin/sudo":    true, // every sudo invocation reads this
		"/usr/sbin/sudo":   true,
		"/usr/sbin/visudo": true,
	},
	// sudo opens the directory itself before reading files inside it.
	// This matches the bare path "/etc/sudoers.d" (no trailing slash).
	// Files inside it are handled by the prefix match below.
	"/etc/sudoers.d": {
		"/usr/bin/sudo":    true,
		"/usr/sbin/sudo":   true,
		"/usr/sbin/visudo": true,
	},
	// /root/.ssh/authorized_keys — no trusted readers; any access is notable
}

// trustedReaderPrefixes covers path prefixes instead of exact paths.
// Key: file prefix, Value: set of trusted exe paths.
var trustedReaderPrefixes = map[string]map[string]bool{
	"/etc/sudoers.d/": {
		"/usr/bin/sudo":    true,
		"/usr/sbin/sudo":   true,
		"/usr/sbin/visudo": true,
	},
}

// AuditFileReadRule fires when a process reads a file watched by auditd
// with key="read_sensitive", unless it is a known-legitimate reader of that file.
//
// Required auditd rules (/etc/audit/rules.d/ids.rules):
//
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F path=/etc/shadow         -F perm=r -k read_sensitive
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F path=/etc/gshadow        -F perm=r -k read_sensitive
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F path=/etc/sudoers        -F perm=r -k read_sensitive
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F dir=/etc/sudoers.d       -F perm=r -k read_sensitive
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F path=/root/.ssh/authorized_keys -F perm=r -k read_sensitive
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
	lastAlertByKey map[string]time.Time
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

	// Extract the calling binary from Message ("exe=<path>") set by the parser.
	exe := strings.TrimPrefix(event.Message, "exe=")

	// ── Whitelist check: suppress known-legitimate (exe, file) combinations ──
	if isTrustedRead(exe, filePath) {
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

	exeLabel := exe
	if exeLabel == "" {
		exeLabel = "unknown"
	}

	alert := model.NewAlert(
		"Sensitive File Read",
		model.SeverityHigh,
		"credential-access",
		fmt.Sprintf("Sensitive file read by unexpected process: %s → %s (user: %s)", exeLabel, filePath, user),
		event,
		1,
	)

	s.lastAlertByKey[key] = now
	s.lastAlertID[key] = alert.ID

	return []*model.Alert{alert}
}

// isTrustedRead returns true when exe is a known-legitimate reader of filePath.
func isTrustedRead(exe, filePath string) bool {
	// Exact file path match
	if readers, ok := trustedReaders[filePath]; ok {
		if readers[exe] {
			return true
		}
	}

	// Prefix match (e.g. /etc/sudoers.d/*)
	for prefix, readers := range trustedReaderPrefixes {
		if strings.HasPrefix(filePath, prefix) && readers[exe] {
			return true
		}
	}

	return false
}
