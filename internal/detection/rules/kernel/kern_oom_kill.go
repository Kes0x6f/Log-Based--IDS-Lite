package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/helper"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// criticalProcesses are processes whose OOM death is always HIGH severity
// regardless of how many times it happens — their absence breaks core services.
var criticalProcesses = map[string]bool{
	"sshd":       true,
	"systemd":    true,
	"dockerd":    true,
	"containerd": true,
	"postgres":   true,
	"mysqld":     true,
	"nginx":      true,
	"apache2":    true,
}

// KernOOMKillRule fires when the kernel OOM killer terminates a process.
//
// Two tiers:
//   - Critical processes: alert on the very first kill (HIGH severity).
//   - Any other process: alert when Threshold kills occur within Window (MEDIUM).
//
// Repeated kills of the same process during a cooldown update the event count
// rather than creating duplicate alerts.
type KernOOMKillRule struct {
	Threshold int
	Window    time.Duration
	Cooldown  time.Duration
}

func NewKernOOMKillRule() *KernOOMKillRule {
	return &KernOOMKillRule{
		Threshold: 3,
		Window:    5 * time.Minute,
		Cooldown:  10 * time.Minute,
	}
}

func (r *KernOOMKillRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:   "kern",
		Program:     "kernel",
		EventTypes:  []string{"OOM_KILL"},
		DisplayName: "OOM Kill Detected",
		Description: "OOM killer terminates a process. HIGH for critical services, MEDIUM otherwise.",
		Defaults: detection.RuleDefaults{
			Threshold:   3,
			WindowSec:   300,
			CooldownSec: 600,
		},
	}
}

// ── Private state ──────────────────────────────────────────────────────────

type kernOOMState struct {
	killsByProc     map[string][]time.Time
	lastAlertByProc map[string]time.Time
	lastAlertID     map[string]string
}

func newKernOOMState() *kernOOMState {
	return &kernOOMState{
		killsByProc:     make(map[string][]time.Time),
		lastAlertByProc: make(map[string]time.Time),
		lastAlertID:     make(map[string]string),
	}
}

func getKernOOMState(ctx *context.DetectionContext) *kernOOMState {
	if v, ok := ctx.GetPrivate("kern_oom"); ok {
		return v.(*kernOOMState)
	}
	s := newKernOOMState()
	ctx.SetPrivate("kern_oom", s)
	return s
}

// ── Evaluate ───────────────────────────────────────────────────────────────

func (r *KernOOMKillRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext, cfg detection.ResolvedConfig) []*model.Alert {
	s := getKernOOMState(ctx)
	proc := event.Command // set by KernParser
	now := event.Timestamp

	if proc == "" {
		proc = "unknown"
	}

	s.killsByProc[proc] = append(s.killsByProc[proc], now)
	s.killsByProc[proc] = helper.PruneOld(s.killsByProc[proc], now, cfg.Window)
	count := len(s.killsByProc[proc])

	isCritical := criticalProcesses[proc]

	// Only alert if threshold met, or process is critical (threshold = 1)
	detail := event.ThreatDetail
	threshold := cfg.Threshold
	if isCritical {
		threshold = 1
		detail += " critical:yes"
	} else {
		detail += " critical:no"
	}
	event.ThreatDetail = detail

	if count < threshold {
		return nil
	}

	last := s.lastAlertByProc[proc]
	inCooldown := !last.IsZero() && now.Sub(last) <= cfg.Cooldown

	if inCooldown {
		if id := s.lastAlertID[proc]; id != "" {
			return []*model.Alert{{
				IsUpdate:        true,
				OriginalAlertID: id,
				EventCount:      count,
			}}
		}
		return nil
	}

	severity := model.SeverityMedium
	if isCritical {
		severity = model.SeverityHigh
	}

	alert := model.NewAlert(
		"OOM Kill Detected",
		severity,
		"stability",
		fmt.Sprintf("OOM killer terminated process %s (%d times in %v)", proc, count, cfg.Window),
		event,
		count,
	)

	s.lastAlertByProc[proc] = now
	s.lastAlertID[proc] = alert.ID

	return []*model.Alert{alert}
}
