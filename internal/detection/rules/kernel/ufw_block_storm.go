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
		LogSource:  "ufw",
		Program:    "kernel",
		EventTypes: []string{"FW_BLOCK"},
	}
}

// ── Private state ──────────────────────────────────────────────────────────

type ufwBlockStormState struct {
	allBlocks   []time.Time // global ring buffer of block timestamps
	lastAlertAt time.Time
	lastAlertID string
}

func newUFWBlockStormState() *ufwBlockStormState {
	return &ufwBlockStormState{}
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

func (r *UFWBlockStormRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {
	s := getUFWBlockStormState(ctx)
	now := event.Timestamp

	for i := 0; i < event.EventCount; i++ {
		s.allBlocks = append(s.allBlocks, now)
	}
	s.allBlocks = helper.PruneOld(s.allBlocks, now, r.Window)

	total := len(s.allBlocks)
	if total < r.Threshold {
		return nil
	}

	inCooldown := !s.lastAlertAt.IsZero() && now.Sub(s.lastAlertAt) <= r.Cooldown

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

	alert := model.NewAlert(
		"UFW Block Storm",
		model.SeverityCritical,
		"dos",
		fmt.Sprintf("%d firewall blocks within %v — possible DDoS or botnet sweep", total, r.Window),
		event,
		total,
	)

	s.lastAlertAt = now
	s.lastAlertID = alert.ID

	return []*model.Alert{alert}
}
