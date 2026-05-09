package rule

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// UFWPortScanRule fires when a single source IP probes many distinct destination
// ports within a short window — the clearest automated port-scan signature.
type UFWPortScanRule struct {
	Threshold int           // distinct ports required to alert
	Window    time.Duration // sliding window
	Cooldown  time.Duration // minimum gap between alerts for the same IP
}

func NewUFWPortScanRule() *UFWPortScanRule {
	return &UFWPortScanRule{
		Threshold: 6,
		Window:    1 * time.Minute,
		Cooldown:  5 * time.Minute,
	}
}

func (r *UFWPortScanRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:   "ufw",
		Program:     "kernel",
		EventTypes:  []string{"FW_BLOCK"},
		DisplayName: "UFW Port Scan Detected",
		Description: "Single source IP hits 10+ distinct destination ports within 1 minute — automated scan.",
		Defaults: detection.RuleDefaults{
			Threshold:   6,
			WindowSec:   60,
			CooldownSec: 300,
		},
	}
}

// ── Private state ──────────────────────────────────────────────────────────

type ufwPortScanState struct {
	// portsByIP tracks each (port → last-seen timestamp) per source IP
	portsByIP   map[string]map[string]time.Time
	lastAlertIP map[string]time.Time
	lastAlertID map[string]string
}

func newUFWPortScanState() *ufwPortScanState {
	return &ufwPortScanState{
		portsByIP:   make(map[string]map[string]time.Time),
		lastAlertIP: make(map[string]time.Time),
		lastAlertID: make(map[string]string),
	}
}

func getUFWPortScanState(ctx *context.DetectionContext) *ufwPortScanState {
	if v, ok := ctx.GetPrivate("ufw_port_scan"); ok {
		return v.(*ufwPortScanState)
	}
	s := newUFWPortScanState()
	ctx.SetPrivate("ufw_port_scan", s)
	return s
}

// ── Evaluate ───────────────────────────────────────────────────────────────

func (r *UFWPortScanRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext, cfg detection.ResolvedConfig) []*model.Alert {
	s := getUFWPortScanState(ctx)
	ip := event.SourceIP
	port := event.Port
	now := event.Timestamp

	if ip == "" || port == "" {
		return nil
	}

	if s.portsByIP[ip] == nil {
		s.portsByIP[ip] = make(map[string]time.Time)
	}

	// Record this port hit
	s.portsByIP[ip][port] = now

	// Prune ports older than the window
	for p, t := range s.portsByIP[ip] {
		if now.Sub(t) > cfg.Window {
			delete(s.portsByIP[ip], p)
		}
	}

	distinctPorts := len(s.portsByIP[ip])
	if distinctPorts < cfg.Threshold {
		return nil
	}

	last := s.lastAlertIP[ip]
	inCooldown := !last.IsZero() && now.Sub(last) <= cfg.Cooldown

	if inCooldown {
		if id := s.lastAlertID[ip]; id != "" {
			return []*model.Alert{{
				IsUpdate:        true,
				OriginalAlertID: id,
				EventCount:      distinctPorts,
			}}
		}
		return nil
	}

	ports := make([]string, 0, len(s.portsByIP[ip]))
	for p := range s.portsByIP[ip] {
		ports = append(ports, p)
	}
	// Sort numerically by converting to int — or lexically is fine for display
	sort.Strings(ports)

	const maxPortShow = 10
	shown := ports
	suffix := ""
	if len(ports) > maxPortShow {
		shown = ports[:maxPortShow]
		suffix = fmt.Sprintf(",…+%d", len(ports)-maxPortShow)
	}

	event.PortList = strings.Join(shown, ",") + suffix
	event.FailCount = distinctPorts

	alert := model.NewAlert(
		"UFW Port Scan Detected",
		model.SeverityHigh,
		"reconnaissance",
		fmt.Sprintf("IP %s probed %d distinct ports in %v [%s%s]", ip, distinctPorts, r.Window, strings.Join(shown, ","), suffix),
		event,
		distinctPorts,
	)

	s.lastAlertIP[ip] = now
	s.lastAlertID[ip] = alert.ID

	return []*model.Alert{alert}
}
