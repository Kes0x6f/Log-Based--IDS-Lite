package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// sensitiveBinaries is the set of process names whose segfaults warrant
// an immediate alert. A crash in an authentication or privilege binary can
// signal exploitation, memory-corruption attacks, or corrupted install.
var sensitiveBinaries = map[string]bool{
	"sshd":        true, // remote auth daemon — crash may indicate exploit
	"sudo":        true, // privilege escalation path
	"su":          true,
	"passwd":      true, // credential management
	"login":       true,
	"polkitd":     true, // PolicyKit — local priv-esc target
	"dbus-daemon": true, // IPC bus — exploit pivot
	"systemd":     true, // init — crash = system instability or exploit
	"cron":        true, // persistent execution — crash may indicate tampering
}

// KernSegfaultRule fires when a sensitive binary produces a segmentation fault.
//
// A per-binary cooldown prevents floods from a crashing-loop process while
// still alerting on the first occurrence and updating the count during cooldown.
type KernSegfaultRule struct {
	Cooldown time.Duration
}

func NewKernSegfaultRule() *KernSegfaultRule {
	return &KernSegfaultRule{
		Cooldown: 10 * time.Minute,
	}
}

func (r *KernSegfaultRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:   "kern",
		Program:     "kernel",
		EventTypes:  []string{"SEGFAULT"},
		DisplayName: "Sensitive Binary Segfault",
		Description: "sshd, sudo, su, passwd, or systemd crashes — may indicate an exploitation attempt.",
		Defaults: detection.RuleDefaults{
			Threshold:   0,
			WindowSec:   0,
			CooldownSec: 600,
		},
	}
}

// ── Private state ──────────────────────────────────────────────────────────

type kernSegfaultState struct {
	lastAlertByBin map[string]time.Time
	lastAlertID    map[string]string
	countByBin     map[string]int
}

func newKernSegfaultState() *kernSegfaultState {
	return &kernSegfaultState{
		lastAlertByBin: make(map[string]time.Time),
		lastAlertID:    make(map[string]string),
		countByBin:     make(map[string]int),
	}
}

func getKernSegfaultState(ctx *context.DetectionContext) *kernSegfaultState {
	if v, ok := ctx.GetPrivate("kern_segfault"); ok {
		return v.(*kernSegfaultState)
	}
	s := newKernSegfaultState()
	ctx.SetPrivate("kern_segfault", s)
	return s
}

// ── Evaluate ───────────────────────────────────────────────────────────────

func (r *KernSegfaultRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext, cfg detection.ResolvedConfig) []*model.Alert {
	bin := event.Command // set by KernParser
	now := event.Timestamp

	if bin == "" || !sensitiveBinaries[bin] {
		return nil
	}

	s := getKernSegfaultState(ctx)
	s.countByBin[bin]++
	count := s.countByBin[bin]

	last := s.lastAlertByBin[bin]
	inCooldown := !last.IsZero() && now.Sub(last) <= cfg.Cooldown

	if inCooldown {
		if id := s.lastAlertID[bin]; id != "" {
			return []*model.Alert{{
				IsUpdate:        true,
				OriginalAlertID: id,
				EventCount:      count,
			}}
		}
		return nil
	}

	// Reset count on new alert window
	s.countByBin[bin] = 1

	alert := model.NewAlert(
		"Sensitive Binary Segfault",
		model.SeverityHigh,
		"exploitation",
		fmt.Sprintf("Security-sensitive process %s crashed with segfault (count: %d)", bin, count),
		event,
		count,
	)

	s.lastAlertByBin[bin] = now
	s.lastAlertID[bin] = alert.ID

	return []*model.Alert{alert}
}
