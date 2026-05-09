package rule

import (
	"fmt"
	"strings"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// methodMeta describes why a given HTTP method is notable and how severe it is.
type methodMeta struct {
	Severity model.Severity
	Reason   string
}

// suspiciousMethodDetails maps HTTP method → explanation + severity.
var suspiciousMethodDetails = map[string]methodMeta{
	"TRACE": {
		Severity: model.SeverityHigh,
		Reason:   "XST (Cross-Site Tracing) attack vector — reveals auth headers to scripts",
	},
	"CONNECT": {
		Severity: model.SeverityHigh,
		Reason:   "proxy tunnel request — used to bypass firewalls or proxy HTTPS traffic",
	},
	"OPTIONS": {
		Severity: model.SeverityMedium,
		Reason:   "server capability enumeration — common first step in recon",
	},
	"PUT": {
		Severity: model.SeverityMedium,
		Reason:   "file upload attempt — may allow writing arbitrary files to the server",
	},
	"DELETE": {
		Severity: model.SeverityMedium,
		Reason:   "file deletion attempt",
	},
	"PATCH": {
		Severity: model.SeverityMedium,
		Reason:   "partial resource modification",
	},
}

// WebMethodRule fires when an HTTP request uses an unusual method.
// A per-(IP, method) cooldown deduplicates scanner traffic while keeping
// the alert log clean.
type WebMethodRule struct {
	Cooldown time.Duration
}

func NewWebMethodRule() *WebMethodRule {
	return &WebMethodRule{
		Cooldown: 15 * time.Minute,
	}
}

func (r *WebMethodRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:  "web",
		Program:    "httpd",
		EventTypes: []string{"HTTP_METHOD"},
	}
}

// ── Private state ──────────────────────────────────────────────────────────

type webMethodState struct {
	lastAlertByKey map[string]time.Time // "ip:method"
	lastAlertID    map[string]string
	countByKey     map[string]int
}

func newWebMethodState() *webMethodState {
	return &webMethodState{
		lastAlertByKey: make(map[string]time.Time),
		lastAlertID:    make(map[string]string),
		countByKey:     make(map[string]int),
	}
}

func getWebMethodState(ctx *context.DetectionContext) *webMethodState {
	if v, ok := ctx.GetPrivate("web_method"); ok {
		return v.(*webMethodState)
	}
	s := newWebMethodState()
	ctx.SetPrivate("web_method", s)
	return s
}

// ── Evaluate ───────────────────────────────────────────────────────────────

func (r *WebMethodRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {
	ip := event.SourceIP
	now := event.Timestamp

	if ip == "" || event.Command == "" {
		return nil
	}

	// Extract method and URI from "METHOD /uri" stored in Command.
	// Both are needed: TRACE / is recon noise; DELETE /api/users/1 is active attack.
	parts := strings.SplitN(event.Command, " ", 2)
	method := strings.ToUpper(parts[0])
	uri := ""
	if len(parts) == 2 {
		uri = parts[1]
	}

	meta, ok := suspiciousMethodDetails[method]
	if !ok {
		return nil
	}

	s := getWebMethodState(ctx)
	key := ip + ":" + method
	s.countByKey[key]++
	count := s.countByKey[key]

	last := s.lastAlertByKey[key]
	inCooldown := !last.IsZero() && now.Sub(last) <= r.Cooldown

	if inCooldown {
		if id := s.lastAlertID[key]; id != "" {
			return []*model.Alert{{
				IsUpdate:        true,
				OriginalAlertID: id,
				EventCount:      count,
			}}
		}
		return nil
	}

	// ── Enrichment ────────────────────────────────────────────────────────
	// FailCount: how many times this IP has used this method in this cooldown
	// window — 1 OPTIONS is recon curiosity; 50 is a scanner.
	//
	// ThreatDetail: method + URI surface what the attacker was actually
	// targeting, which matters most for PUT/DELETE/PATCH where the endpoint
	// determines the severity (DELETE /healthz vs DELETE /api/admin/users).
	uriShort := uri
	if len(uriShort) > 80 {
		uriShort = uriShort[:77] + "..."
	}

	event.FailCount = count
	event.ThreatDetail = fmt.Sprintf("method:%s uri:%s",
		method, strings.ReplaceAll(uriShort, " ", "-"))

	s.countByKey[key] = 1

	alert := model.NewAlert(
		"Unusual HTTP Method",
		meta.Severity,
		"web-probe",
		fmt.Sprintf("IP %s: %s %s — %s", ip, method, uri, meta.Reason),
		event,
		count,
	)
	s.lastAlertByKey[key] = now
	s.lastAlertID[key] = alert.ID

	return []*model.Alert{alert}
}
