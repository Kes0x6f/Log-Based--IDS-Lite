package rule

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// capsetWhitelist contains binaries that legitimately call capset to DROP
// capabilities as part of normal privilege reduction / sandboxing.
// These are safe and extremely noisy — suppress them entirely.
var capsetWhitelist = map[string]bool{
	"/lib/systemd/systemd":                           true,
	"/usr/lib/systemd/systemd":                       true,
	"/usr/lib/systemd/systemd-executor":              true, // service launcher — sets caps for each spawned service
	"/usr/bin/dbus-daemon":                           true,
	"/usr/sbin/sshd":                                 true,
	"/usr/bin/ssh":                                   true,
	"/usr/sbin/polkitd":                              true,
	"/usr/bin/containerd":                            true,
	"/usr/bin/dockerd":                               true,
	"/usr/bin/cron":                                  true,
	"/usr/sbin/cron":                                 true,
	"/usr/lib/postfix/master":                        true,
	"/usr/bin/bash":                                  true,
	"/usr/bin/sudo":                                  true, // setuid-root binary — full cap set on every invocation
	"/usr/sbin/sudo":                                 true,
	"/snap/firefox/8191/usr/lib/firefox/firefox":     true,
	"/snap/snapd/26865/usr/lib/snapd/snap-confine":   true,
	"/snap/snapd/26865/usr/lib/snapd/snap-update-ns": true,
	"/usr/bin/setpriv":                               true,
	"/usr/libexec/gdm-session-worker":                true,
	"/usr/sbin/avahi-daemon":                         true,
	"/usr/sbin/auditctl":                             true,
}

// dangerousCaps are capability bits whose presence warrants CRITICAL severity.
// Bit positions match Linux capability constants.
var dangerousCaps = map[int]string{
	0:  "CAP_CHOWN",
	1:  "CAP_DAC_OVERRIDE",
	6:  "CAP_SETUID",
	7:  "CAP_SETGID",
	19: "CAP_SYS_PTRACE",
	21: "CAP_SYS_ADMIN",
	38: "CAP_AUDIT_WRITE",
}

type AuditCapsetRule struct {
	Cooldown time.Duration
}

func NewAuditCapsetRule() *AuditCapsetRule {
	return &AuditCapsetRule{
		Cooldown: 30 * time.Minute, // increased from 10 — these are rare genuine events
	}
}

func (r *AuditCapsetRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:  "audit",
		Program:    "auditd",
		EventTypes: []string{"CAPSET"},
	}
}

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

func (r *AuditCapsetRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {
	exe := event.Command
	user := event.Username
	now := event.Timestamp

	if exe == "" {
		exe = "unknown"
	}

	// ── Filter 1: known-safe system binaries ──────────────────────────────
	if capsetWhitelist[exe] {
		return nil
	}

	// ── Filter 2: capability drop to zero is safe ─────────────────────────
	// event.Message was set by the parser: "cap_prm=<hex> cap_eff=<hex>"
	capPrm, capEff := parseCapFields(event.Message)

	isCapDrop := capPrm == 0 && capEff == 0
	if isCapDrop {
		// Dropping all capabilities is the normal security-hardening pattern.
		// Only alert if it comes from an unknown binary (belt-and-suspenders).
		return nil
	}

	// ── Filter 3: no capability data from parser — unknown but suspicious ─
	// If the parser couldn't extract cap values, still alert but at MEDIUM
	// so genuine unknown binaries don't go silently unnoticed.

	// ── Determine severity based on which caps are being set ──────────────
	severity, capName := classifyCapabilities(capPrm | capEff)

	s := getAuditCapsetState(ctx)
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

	msg := fmt.Sprintf(
		"Process %s (user: %s) gained capabilities at runtime (cap_prm=0x%x cap_eff=0x%x)",
		exe, user, capPrm, capEff,
	)
	if capName != "" {
		msg = fmt.Sprintf(
			"Process %s (user: %s) gained dangerous capability %s — possible privilege escalation",
			exe, user, capName,
		)
	}

	alert := model.NewAlert(
		"Capability Change Detected",
		severity,
		"privilege-escalation",
		msg,
		event,
		count,
	)

	s.lastAlertByKey[key] = now
	s.lastAlertID[key] = alert.ID

	return []*model.Alert{alert}
}

// parseCapFields reads "cap_prm=<hex> cap_eff=<hex>" from Message.
// Returns (0, 0) when the parser didn't populate the field.
func parseCapFields(msg string) (capPrm uint64, capEff uint64) {
	for _, field := range strings.Fields(msg) {
		kv := strings.SplitN(field, "=", 2)
		if len(kv) != 2 {
			continue
		}
		val, err := strconv.ParseUint(kv[1], 16, 64)
		if err != nil {
			continue
		}
		switch kv[0] {
		case "cap_prm":
			capPrm = val
		case "cap_eff":
			capEff = val
		}
	}
	return
}

// classifyCapabilities returns severity and a human-readable cap name for the
// most dangerous capability bit present in the combined set.
// Falls back to HIGH + empty name when no specifically dangerous bit is set
// but capabilities are non-zero.
func classifyCapabilities(combined uint64) (model.Severity, string) {
	for bit, name := range dangerousCaps {
		if combined&(1<<uint(bit)) != 0 {
			return model.SeverityCritical, name
		}
	}
	if combined != 0 {
		return model.SeverityHigh, ""
	}
	return model.SeverityMedium, ""
}
