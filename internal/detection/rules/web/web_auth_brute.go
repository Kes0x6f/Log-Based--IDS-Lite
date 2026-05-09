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

// WebAuthBruteRule detects brute-force attempts against HTTP login endpoints.
// The parser emits HTTP_AUTH_FAIL for:
//   - Any 401 response (authentication required — the server challenged the client)
//   - Any 403 response on a POST request (login form rejected)
//
// Multiple 401/403 responses from the same IP within a short window indicate
// automated credential testing against a web login panel.
type WebAuthBruteRule struct {
	Threshold int
	Window    time.Duration
	Cooldown  time.Duration
}

func NewWebAuthBruteRule() *WebAuthBruteRule {
	return &WebAuthBruteRule{
		Threshold: 5,
		Window:    3 * time.Minute,
		Cooldown:  10 * time.Minute,
	}
}

func (r *WebAuthBruteRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:   "web",
		Program:     "httpd",
		EventTypes:  []string{"HTTP_AUTH_FAIL"},
		DisplayName: "Web Login Brute Force",
		Description: "5+ HTTP 401/403 responses to the same IP in 3 minutes — credential stuffing or login brute force.",
		Defaults: detection.RuleDefaults{
			Threshold:   5,
			WindowSec:   180,
			CooldownSec: 600,
		},
	}
}

// ── Private state ──────────────────────────────────────────────────────────

type webAuthBruteState struct {
	failsByIP   map[string][]time.Time
	lastAlertIP map[string]time.Time
	lastAlertID map[string]string
}

func newWebAuthBruteState() *webAuthBruteState {
	return &webAuthBruteState{
		failsByIP:   make(map[string][]time.Time),
		lastAlertIP: make(map[string]time.Time),
		lastAlertID: make(map[string]string),
	}
}

func getWebAuthBruteState(ctx *context.DetectionContext) *webAuthBruteState {
	if v, ok := ctx.GetPrivate("web_auth_brute"); ok {
		return v.(*webAuthBruteState)
	}
	s := newWebAuthBruteState()
	ctx.SetPrivate("web_auth_brute", s)
	return s
}

// ── Evaluate ───────────────────────────────────────────────────────────────

func (r *WebAuthBruteRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext, cfg detection.ResolvedConfig) []*model.Alert {
	s := getWebAuthBruteState(ctx)
	ip := event.SourceIP
	now := event.Timestamp

	if ip == "" {
		return nil
	}

	s.failsByIP[ip] = append(s.failsByIP[ip], now)
	s.failsByIP[ip] = helper.PruneOld(s.failsByIP[ip], now, cfg.Window)
	count := len(s.failsByIP[ip])

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

	endpoint := ""
	if parts := strings.SplitN(event.Command, " ", 2); len(parts) == 2 {
		endpoint = parts[1]
	}

	event.FailCount = count
	if endpoint != "" {
		event.ThreatDetail = fmt.Sprintf("endpoint:%s", endpoint)
	}

	alert := model.NewAlert(
		"Web Login Brute Force",
		model.SeverityHigh,
		"credential-access",
		fmt.Sprintf("IP %s: %d auth failures in %v%s",
			ip, count, cfg.Window,
			func() string {
				if endpoint != "" {
					return " on " + endpoint
				}
				return ""
			}()),
		event,
		count,
	)
	s.lastAlertIP[ip] = now
	s.lastAlertID[ip] = alert.ID

	return []*model.Alert{alert}
}
