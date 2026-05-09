package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/helper"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// UFWRepeatedBlockRule fires when the same source IP accumulates many blocked
// packets within a window. Unlike a port scan (which measures breadth across
// ports), this measures raw persistence — hammering any port(s) repeatedly.
type UFWRepeatedBlockRule struct {
	Threshold int
	Window    time.Duration
}

func NewUFWRepeatedBlockRule() *UFWRepeatedBlockRule {
	return &UFWRepeatedBlockRule{
		Threshold: 20,
		Window:    2 * time.Minute,
	}
}

func (r *UFWRepeatedBlockRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:   "ufw",
		Program:     "kernel",
		EventTypes:  []string{"FW_BLOCK"},
		DisplayName: "UFW Repeated Block",
		Description: "Same source IP accumulates 20+ firewall blocks in 2 minutes — persistent probing.",
		Defaults: detection.RuleDefaults{
			Threshold:   20,
			WindowSec:   120,
			CooldownSec: 120,
		},
	}
}

// ── Private state ──────────────────────────────────────────────────────────

type ufwRepeatedBlockState struct {
	blocksByIP   map[string][]time.Time
	lastAlertIP  map[string]time.Time
	lastAlertID  map[string]string
	runningCount map[string]int
}

func newUFWRepeatedBlockState() *ufwRepeatedBlockState {
	return &ufwRepeatedBlockState{
		blocksByIP:   make(map[string][]time.Time),
		lastAlertIP:  make(map[string]time.Time),
		lastAlertID:  make(map[string]string),
		runningCount: make(map[string]int),
	}
}

func getUFWRepeatedBlockState(ctx *context.DetectionContext) *ufwRepeatedBlockState {
	if v, ok := ctx.GetPrivate("ufw_repeated_block"); ok {
		return v.(*ufwRepeatedBlockState)
	}
	s := newUFWRepeatedBlockState()
	ctx.SetPrivate("ufw_repeated_block", s)
	return s
}

// ── Evaluate ───────────────────────────────────────────────────────────────

func (r *UFWRepeatedBlockRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext, cfg detection.ResolvedConfig) []*model.Alert {
	s := getUFWRepeatedBlockState(ctx)
	ip := event.SourceIP
	now := event.Timestamp

	if ip == "" {
		return nil
	}

	for i := 0; i < event.EventCount; i++ {
		s.blocksByIP[ip] = append(s.blocksByIP[ip], now)
	}
	s.blocksByIP[ip] = helper.PruneOld(s.blocksByIP[ip], now, cfg.Window)

	count := len(s.blocksByIP[ip])
	if count < cfg.Threshold {
		return nil
	}

	last := s.lastAlertIP[ip]
	inCooldown := !last.IsZero() && now.Sub(last) <= cfg.Cooldown

	if inCooldown {
		s.runningCount[ip] += event.EventCount
		if id := s.lastAlertID[ip]; id != "" {
			return []*model.Alert{{
				IsUpdate:        true,
				OriginalAlertID: id,
				EventCount:      count,
			}}
		}
		return nil
	}

	event.FailCount = count

	alert := model.NewAlert(
		"UFW Repeated Block",
		model.SeverityMedium,
		"reconnaissance",
		fmt.Sprintf("IP %s blocked %d times within %v", ip, count, cfg.Window),
		event,
		count,
	)

	s.lastAlertIP[ip] = now
	s.lastAlertID[ip] = alert.ID
	s.runningCount[ip] = 0

	return []*model.Alert{alert}
}
