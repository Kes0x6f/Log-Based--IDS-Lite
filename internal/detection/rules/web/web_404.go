package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/helper"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// Web404Rule detects path enumeration — the technique where a scanner
// requests many paths in sequence looking for existing files, admin panels,
// backup files, or exposed configuration.
//
// Unlike a port scan (many ports, one IP), a 404-rate alert fires on many
// distinct URIs returning 404. A single IP hitting 15+ missing paths within
// a minute is nearly always automated.
type Web404Rule struct {
	Threshold int
	Window    time.Duration
	Cooldown  time.Duration
}

func NewWeb404Rule() *Web404Rule {
	return &Web404Rule{
		Threshold: 15,
		Window:    1 * time.Minute,
		Cooldown:  5 * time.Minute,
	}
}

func (r *Web404Rule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:   "web",
		Program:     "httpd",
		EventTypes:  []string{"HTTP_404"},
		DisplayName: "Web Path Enumeration",
		Description: "Single IP generates 15+ HTTP 404 responses in 1 minute — automated path discovery scan.",
		Defaults: detection.RuleDefaults{
			Threshold:   15,
			WindowSec:   60,
			CooldownSec: 300,
		},
	}
}

// ── Private state ──────────────────────────────────────────────────────────

type web404State struct {
	hitsByIP    map[string][]time.Time
	lastAlertIP map[string]time.Time
	lastAlertID map[string]string
}

func newWeb404State() *web404State {
	return &web404State{
		hitsByIP:    make(map[string][]time.Time),
		lastAlertIP: make(map[string]time.Time),
		lastAlertID: make(map[string]string),
	}
}

func getWeb404State(ctx *context.DetectionContext) *web404State {
	if v, ok := ctx.GetPrivate("web_404"); ok {
		return v.(*web404State)
	}
	s := newWeb404State()
	ctx.SetPrivate("web_404", s)
	return s
}

// ── Evaluate ───────────────────────────────────────────────────────────────

func (r *Web404Rule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext, cfg detection.ResolvedConfig) []*model.Alert {
	s := getWeb404State(ctx)
	ip := event.SourceIP
	now := event.Timestamp

	if ip == "" {
		return nil
	}

	s.hitsByIP[ip] = append(s.hitsByIP[ip], now)
	s.hitsByIP[ip] = helper.PruneOld(s.hitsByIP[ip], now, cfg.Window)
	count := len(s.hitsByIP[ip])

	if count < cfg.Threshold {
		return nil
	}

	last := s.lastAlertIP[ip]
	inCooldown := !last.IsZero() && now.Sub(last) <= cfg.Cooldown

	if inCooldown {
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
		"Web Path Enumeration",
		model.SeverityMedium,
		"reconnaissance",
		fmt.Sprintf("IP %s: %d 404 responses in %v — path enumeration", ip, count, cfg.Window),
		event,
		count,
	)
	s.lastAlertIP[ip] = now
	s.lastAlertID[ip] = alert.ID

	return []*model.Alert{alert}
}
