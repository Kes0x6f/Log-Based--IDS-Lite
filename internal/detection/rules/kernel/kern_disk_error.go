package rule

import (
	"fmt"
	"strings"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/helper"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// KernDiskErrorRule fires when the same block device accumulates repeated I/O
// errors within a sliding window.
//
// Severity tiers (both per device per window):
//   - ≥ LowThreshold  errors → MEDIUM (early warning, possible hardware fault)
//   - ≥ HighThreshold errors → HIGH   (likely failing device or active tampering)
//
// From a security standpoint disk errors matter because:
//   - An attacker deliberately corrupting a filesystem will generate I/O errors.
//   - A dying disk used to store evidence (logs, forensic images) is itself
//     a security concern.
//   - Sudden errors on a previously healthy disk during an active incident
//     are suspicious.
type KernDiskErrorRule struct {
	LowThreshold  int
	HighThreshold int
	Window        time.Duration
	Cooldown      time.Duration
}

func NewKernDiskErrorRule() *KernDiskErrorRule {
	return &KernDiskErrorRule{
		LowThreshold:  5,
		HighThreshold: 20,
		Window:        5 * time.Minute,
		Cooldown:      15 * time.Minute,
	}
}

func (r *KernDiskErrorRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:  "kern",
		Program:    "kernel",
		EventTypes: []string{"DISK_ERROR"},
	}
}

// ── Private state ──────────────────────────────────────────────────────────

type kernDiskErrorState struct {
	errorsByDev    map[string][]time.Time
	lastAlertByDev map[string]time.Time
	lastAlertID    map[string]string
}

func newKernDiskErrorState() *kernDiskErrorState {
	return &kernDiskErrorState{
		errorsByDev:    make(map[string][]time.Time),
		lastAlertByDev: make(map[string]time.Time),
		lastAlertID:    make(map[string]string),
	}
}

func getKernDiskErrorState(ctx *context.DetectionContext) *kernDiskErrorState {
	if v, ok := ctx.GetPrivate("kern_disk_error"); ok {
		return v.(*kernDiskErrorState)
	}
	s := newKernDiskErrorState()
	ctx.SetPrivate("kern_disk_error", s)
	return s
}

// ── Evaluate ───────────────────────────────────────────────────────────────

func (r *KernDiskErrorRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {
	s := getKernDiskErrorState(ctx)
	dev := event.Command // device name set by KernParser
	now := event.Timestamp

	if dev == "" {
		dev = "unknown"
	}

	s.errorsByDev[dev] = append(s.errorsByDev[dev], now)
	s.errorsByDev[dev] = helper.PruneOld(s.errorsByDev[dev], now, r.Window)
	count := len(s.errorsByDev[dev])

	if count < r.LowThreshold {
		return nil
	}

	last := s.lastAlertByDev[dev]
	inCooldown := !last.IsZero() && now.Sub(last) <= r.Cooldown

	if inCooldown {
		if id := s.lastAlertID[dev]; id != "" {
			return []*model.Alert{{
				IsUpdate:        true,
				OriginalAlertID: id,
				EventCount:      count,
			}}
		}
		return nil
	}

	severity := model.SeverityMedium
	if count >= r.HighThreshold {
		severity = model.SeverityHigh
	}

	event.FailCount = count

	if dev != "unknown" && !strings.Contains(event.ThreatDetail, "dev:") {
		event.ThreatDetail += fmt.Sprintf(" dev:%s", dev)
	}

	alert := model.NewAlert(
		"Disk I/O Errors Detected",
		severity,
		"hardware",
		fmt.Sprintf("Device %s: %d I/O errors within %v — possible hardware failure or tampering", dev, count, r.Window),
		event,
		count,
	)

	s.lastAlertByDev[dev] = now
	s.lastAlertID[dev] = alert.ID

	return []*model.Alert{alert}
}
