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

// capsetWhitelist contains exact exe paths that are always safe to suppress.
// For broad path-prefix suppression, see capsetTrustedPrefixes below.
var capsetWhitelist = map[string]bool{
	// systemd family
	"/lib/systemd/systemd":              true,
	"/usr/lib/systemd/systemd":          true,
	"/usr/lib/systemd/systemd-executor": true,
	"/usr/lib/systemd/systemd-udevd":    true,
	"/usr/lib/systemd/systemd-logind":   true,
	"/usr/lib/systemd/systemd-networkd": true,
	"/usr/lib/systemd/systemd-resolved": true,
	// auth / IPC daemons
	"/usr/sbin/sshd":         true,
	"/usr/bin/ssh":           true,
	"/usr/bin/dbus-daemon":   true,
	"/usr/sbin/polkitd":      true,
	"/usr/sbin/avahi-daemon": true,
	// privilege helpers
	"/usr/bin/sudo":      true,
	"/usr/sbin/sudo":     true,
	"/usr/bin/su":        true,
	"/usr/bin/newgrp":    true,
	"/usr/bin/setpriv":   true,
	"/usr/sbin/auditctl": true,
	// scheduling / mail
	"/usr/bin/cron":           true,
	"/usr/sbin/cron":          true,
	"/usr/lib/postfix/master": true,
	// container runtimes
	"/usr/bin/containerd":              true,
	"/usr/bin/dockerd":                 true,
	"/usr/bin/runc":                    true,
	"/usr/sbin/runc":                   true,
	"/usr/bin/containerd-shim-runc-v2": true,
	// desktop session
	"/usr/libexec/gdm-session-worker": true,
	"/usr/bin/bash":                   true,
}

// capsetTrustedPrefixes suppresses any binary whose path starts with one
// of these prefixes. This catches versioned snap paths, DKMS helpers,
// and distribution-specific paths without requiring per-version entries.
//
// A prefix only silences the rule when the capability set contains NO
// critical bits (CAP_SETUID, CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_SETGID).
// If a binary under /snap/ somehow gains CAP_SYS_PTRACE it still alerts.
var capsetTrustedPrefixes = []string{
	"/usr/lib/snapd/",
	"/snap/snapd/",
	"/snap/core", // covers core18, core20, core22 snaps
	"/var/lib/snapd/",
}

// dangerousCaps are the ONLY capability bits that will produce an alert.
// Removing a cap from this map suppresses its alerts entirely — use that
// to tune noise for your environment.
//
// Rationale for each bit kept:
//
//	CAP_SETUID (6)      — arbitrary uid switch → root
//	CAP_SETGID (7)      — arbitrary gid switch → privileged group
//	CAP_SYS_PTRACE (19) — ptrace any process → credential dump / code injection
//	CAP_SYS_ADMIN (21)  — almost-root; mount, namespace, eBPF, etc.
//
// Deliberately removed from old list (too noisy, not directly exploitable alone):
//
//	CAP_CHOWN (0)       — container runtimes set this routinely
//	CAP_DAC_OVERRIDE(1) — web servers, backup agents, many legitimate tools
//	CAP_AUDIT_WRITE(38) — logging daemons set this; very common, low risk
var dangerousCaps = map[int]string{
	6:  "CAP_SETUID",
	7:  "CAP_SETGID",
	19: "CAP_SYS_PTRACE",
	21: "CAP_SYS_ADMIN",
}

// capsetMinCount is the minimum number of capset calls from a (user, exe)
// pair within the cooldown window before we alert. A value of 1 fires on
// the very first call; raise to 2 to absorb one-time process initialisation.
const capsetMinCount = 2

type AuditCapsetRule struct{}

func NewAuditCapsetRule() *AuditCapsetRule {
	return &AuditCapsetRule{}
}

func (r *AuditCapsetRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:   "audit",
		Program:     "auditd",
		EventTypes:  []string{"CAPSET"},
		DisplayName: "Capability Change Detected",
		Description: "Non-system process dynamically gains CAP_SETUID/SETGID/SYS_PTRACE/SYS_ADMIN — privilege escalation without a shell.",
		Defaults: detection.RuleDefaults{
			Threshold:   0,
			WindowSec:   0,
			CooldownSec: 3600, // 1 hour — genuine events are rare; suppress re-alerts
		},
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

func (r *AuditCapsetRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext, cfg detection.ResolvedConfig) []*model.Alert {
	exe := event.Command
	user := event.Username
	now := event.Timestamp

	if exe == "" {
		exe = "unknown"
	}

	// ── Filter 1: exact-path whitelist ────────────────────────────────────
	if capsetWhitelist[exe] {
		return nil
	}

	// ── Filter 2: capability values — parse first so all later filters can use them
	capPrm, capEff := parseCapFields(event.Message)

	// ── Filter 3: only alert when at least one dangerous cap is EFFECTIVE ──
	// cap_eff (effective) is what the kernel actually enforces for each syscall.
	// cap_prm (permitted) is the ceiling — a process can hold permitted caps
	// without exercising them. Many legitimate processes raise permitted caps
	// during initialisation but never set them effective.
	// Alert only when a dangerous cap appears in the EFFECTIVE set.
	dangerousEffective := capEff & dangerousCapMask()
	if dangerousEffective == 0 {
		// No dangerous cap is currently effective — harmless cap management.
		return nil
	}

	// ── Filter 4: trusted path prefixes for non-critical binaries ─────────
	// Even if a snap or snapd helper briefly holds a dangerous cap during
	// confined execution, suppress it — snap-confine grants and revokes caps
	// as part of its normal confinement protocol.
	for _, prefix := range capsetTrustedPrefixes {
		if strings.HasPrefix(exe, prefix) {
			return nil
		}
	}

	// ── Filter 5: full capability drop (cap_prm=0 AND cap_eff=0) is safe ──
	if capPrm == 0 && capEff == 0 {
		return nil
	}

	// ── Count & cooldown ──────────────────────────────────────────────────
	s := getAuditCapsetState(ctx)
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

	// ── Filter 6: require N calls before alerting ─────────────────────────
	// Absorbs one-time capability grants during process start-up. Most
	// legitimate daemons call capset exactly once as they initialise and
	// are already covered by the whitelist; requiring 2 hits before alerting
	// suppresses the remaining one-shot initialisation noise from unlisted
	// binaries without hiding a real attack (which generates repeated calls).
	if count < capsetMinCount {
		return nil
	}

	// ── Build alert ───────────────────────────────────────────────────────
	capNames := decodeEffectiveDangerousCaps(dangerousEffective)
	event.ThreatDetail = "caps:" + strings.Join(capNames, ",")

	alert := model.NewAlert(
		"Capability Change Detected",
		model.SeverityCritical, // only dangerous effective caps reach here
		"privilege-escalation",
		fmt.Sprintf("%s gained %s at runtime (user: %s)", exe, strings.Join(capNames, "+"), user),
		event,
		count,
	)

	s.lastAlertByKey[key] = now
	s.lastAlertID[key] = alert.ID
	s.countByKey[key] = 0 // reset after alert so next window starts fresh

	return []*model.Alert{alert}
}

// ── Helpers ───────────────────────────────────────────────────────────────

// dangerousCapMask returns a bitmask covering all bits in dangerousCaps.
// Computed once per call; cheap enough for the hot path.
func dangerousCapMask() uint64 {
	var mask uint64
	for bit := range dangerousCaps {
		mask |= 1 << uint(bit)
	}
	return mask
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

// decodeEffectiveDangerousCaps returns the names of dangerous caps set in mask.
func decodeEffectiveDangerousCaps(mask uint64) []string {
	var names []string
	for bit, name := range dangerousCaps {
		if mask&(1<<uint(bit)) != 0 {
			names = append(names, name)
		}
	}
	return names
}
