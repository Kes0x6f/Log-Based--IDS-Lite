package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/helper"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// UFWBlockStormRule watches the *global* block rate across all source IPs.
// A sudden spike — even from many different IPs — indicates a DDoS, botnet
// sweep, or network scan campaign rather than a single attacker.
type UFWBlockStormRule struct {
	Threshold int           // total blocks within Window before alerting
	Window    time.Duration // sliding window
	Cooldown  time.Duration // minimum gap between consecutive storm alerts
}

func NewUFWBlockStormRule() *UFWBlockStormRule {
	return &UFWBlockStormRule{
		Threshold: 200,
		Window:    1 * time.Minute,
		Cooldown:  5 * time.Minute,
	}
}

func (r *UFWBlockStormRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:   "ufw",
		Program:     "kernel",
		EventTypes:  []string{"FW_BLOCK"},
		DisplayName: "UFW Block Storm",
		Description: "200+ total firewall blocks within 1 minute across all IPs — DDoS or botnet sweep.",
		Defaults: detection.RuleDefaults{
			Threshold:   200,
			WindowSec:   60,
			CooldownSec: 300,
		},
	}
}

// ── Private state ──────────────────────────────────────────────────────────

type ufwBlockStormState struct {
	allBlocks   []time.Time // global ring buffer of block timestamps
	ipCounts    map[string]time.Time
	lastAlertAt time.Time
	lastAlertID string
}

func newUFWBlockStormState() *ufwBlockStormState {
	return &ufwBlockStormState{
		ipCounts: make(map[string]time.Time),
	}
}

func getUFWBlockStormState(ctx *context.DetectionContext) *ufwBlockStormState {
	if v, ok := ctx.GetPrivate("ufw_block_storm"); ok {
		return v.(*ufwBlockStormState)
	}
	s := newUFWBlockStormState()
	ctx.SetPrivate("ufw_block_storm", s)
	return s
}

// ── Evaluate ───────────────────────────────────────────────────────────────

func (r *UFWBlockStormRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext, cfg detection.ResolvedConfig) []*model.Alert {
	s := getUFWBlockStormState(ctx)
	now := event.Timestamp

	for i := 0; i < event.EventCount; i++ {
		s.allBlocks = append(s.allBlocks, now)
	}

	if ip := event.SourceIP; ip != "" {
		s.ipCounts[ip] = now
	}

	s.allBlocks = helper.PruneOld(s.allBlocks, now, cfg.Window)

	for ip, t := range s.ipCounts {
		if now.Sub(t) > cfg.Window {
			delete(s.ipCounts, ip)
		}
	}

	total := len(s.allBlocks)
	if total < cfg.Threshold {
		return nil
	}

	inCooldown := !s.lastAlertAt.IsZero() && now.Sub(s.lastAlertAt) <= cfg.Cooldown

	if inCooldown {
		if s.lastAlertID != "" {
			return []*model.Alert{{
				IsUpdate:        true,
				OriginalAlertID: s.lastAlertID,
				EventCount:      total,
			}}
		}
		return nil
	}

	ipCount := len(s.ipCounts)

	event.FailCount = total
	event.IPCount = ipCount
	event.ThreatDetail = fmt.Sprintf("sources:%d", ipCount)

	alert := model.NewAlert(
		"UFW Block Storm",
		model.SeverityCritical,
		"dos",
		fmt.Sprintf("%d firewall blocks in %v from %d distinct IPs — possible DDoS or botnet sweep", total, cfg.Window, ipCount),
		event,
		total,
	)

	s.lastAlertAt = now
	s.lastAlertID = alert.ID

	return []*model.Alert{alert}
}
