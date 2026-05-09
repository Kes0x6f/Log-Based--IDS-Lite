package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/helper"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// WebFloodRule detects a high total request rate from a single IP,
// regardless of the type of request.
//
// It registers for ALL web event types so every request — whether it is
// a normal GET, a 404, an auth failure, or a probe — is counted toward
// the threshold. This lets it catch floods that are spread across many
// different URIs and request types, where no single-EventType rule would
// accumulate enough hits on its own.
//
// Severity tiers:
//   - ≥ Threshold → MEDIUM (general flood / aggressive crawler)
//   - ≥ CriticalThreshold → HIGH  (likely DDoS or high-volume automated scan)
type WebFloodRule struct {
	Threshold         int
	CriticalThreshold int
	Window            time.Duration
	Cooldown          time.Duration
}

func NewWebFloodRule() *WebFloodRule {
	return &WebFloodRule{
		Threshold:         100,
		CriticalThreshold: 500,
		Window:            1 * time.Minute,
		Cooldown:          5 * time.Minute,
	}
}

func (r *WebFloodRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource: "web",
		Program:   "httpd",
		// Register for every EventType the web parser emits so ALL requests
		// from an IP are counted, not just one category.
		EventTypes: []string{
			"HTTP_REQUEST",
			"HTTP_PROBE",
			"HTTP_404",
			"HTTP_AUTH_FAIL",
			"HTTP_METHOD",
		},
	}
}

// ── Private state ──────────────────────────────────────────────────────────

type webFloodState struct {
	reqsByIP    map[string][]time.Time
	lastAlertIP map[string]time.Time
	lastAlertID map[string]string
}

func newWebFloodState() *webFloodState {
	return &webFloodState{
		reqsByIP:    make(map[string][]time.Time),
		lastAlertIP: make(map[string]time.Time),
		lastAlertID: make(map[string]string),
	}
}

func getWebFloodState(ctx *context.DetectionContext) *webFloodState {
	if v, ok := ctx.GetPrivate("web_flood"); ok {
		return v.(*webFloodState)
	}
	s := newWebFloodState()
	ctx.SetPrivate("web_flood", s)
	return s
}

// ── Evaluate ───────────────────────────────────────────────────────────────

func (r *WebFloodRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {
	s := getWebFloodState(ctx)
	ip := event.SourceIP
	now := event.Timestamp

	if ip == "" {
		return nil
	}

	s.reqsByIP[ip] = append(s.reqsByIP[ip], now)
	s.reqsByIP[ip] = helper.PruneOld(s.reqsByIP[ip], now, r.Window)
	count := len(s.reqsByIP[ip])

	if count < r.Threshold {
		return nil
	}

	last := s.lastAlertIP[ip]
	inCooldown := !last.IsZero() && now.Sub(last) <= r.Cooldown

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

	tier := "MEDIUM"
	severity := model.SeverityMedium
	label := "High Request Rate"
	if count >= r.CriticalThreshold {

		tier = "HIGH"
		severity = model.SeverityHigh
		label = "Extreme Request Rate"
	}

	rate := count // count = requests in the last 1-minute window = requests/min

	event.FailCount = count
	event.ThreatDetail = fmt.Sprintf("rate:%d/min tier:%s", rate, tier)

	alert := model.NewAlert(
		label,
		severity,
		"dos",
		fmt.Sprintf("IP %s sent %d HTTP requests in %v — possible flood or automated scan", ip, count, r.Window),
		event,
		count,
	)
	s.lastAlertIP[ip] = now
	s.lastAlertID[ip] = alert.ID

	return []*model.Alert{alert}
}
