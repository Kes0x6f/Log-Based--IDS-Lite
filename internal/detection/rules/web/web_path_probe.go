package rule

import (
	"fmt"
	"strings"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// probeCategory groups attack patterns into named, severity-tiered families.
type probeCategory struct {
	Name     string
	Severity model.Severity
	Patterns []string
}

// probeCategories is evaluated in order. The first category that matches
// determines the alert name and severity for that request.
var probeCategories = []probeCategory{
	{
		Name:     "RCE / Command Injection",
		Severity: model.SeverityCritical,
		Patterns: []string{
			";cat ", "|cat ", "|id ", "|whoami", "$(id)", "`id`",
			"/bin/bash", "/bin/sh", "cmd.exe", "powershell",
			"php://input", "php://filter", "data://", "expect://",
		},
	},
	{
		Name:     "SQL Injection",
		Severity: model.SeverityCritical,
		Patterns: []string{
			"union select", "union+select",
			"' or '", "'or'1'", "or 1=1",
			"; drop ", ";drop ",
			"information_schema", "xp_cmdshell",
			"waitfor delay", "sleep(", "benchmark(", "load_file(", "into outfile",
		},
	},
	{
		Name:     "XSS Probe",
		Severity: model.SeverityHigh,
		Patterns: []string{
			"<script", "javascript:", "onerror=", "onload=",
			"onmouseover=", "onfocus=", "alert(", "document.cookie",
			"document.write(", "fromcharcode",
		},
	},
	{
		Name:     "Directory Traversal",
		Severity: model.SeverityHigh,
		Patterns: []string{
			"../", "..\\", "%2e%2e", "..%2f",
			"%2e%2e%2f", "%2e%2e%5c", "....//",
			"/etc/passwd", "/etc/shadow", "wp-config.php",
			".env", "/.git/", "/.svn/", "web.config",
		},
	},
}

// WebPathProbeRule fires when the request URI contains an attack pattern.
// The parser already URL-decodes and lowercases the URI before classifying
// the event as HTTP_PROBE, but this rule re-checks the raw Command field
// to categorise the attack and determine the correct severity.
//
// A per-(IP, category) cooldown prevents floods from automated scanners
// while still alerting on first hit and updating the count during cooldown.
type WebPathProbeRule struct {
	Cooldown time.Duration
}

func NewWebPathProbeRule() *WebPathProbeRule {
	return &WebPathProbeRule{
		Cooldown: 5 * time.Minute,
	}
}

func (r *WebPathProbeRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:  "web",
		Program:    "httpd",
		EventTypes: []string{"HTTP_PROBE"},
	}
}

// ── Private state ──────────────────────────────────────────────────────────

type webPathProbeState struct {
	lastAlertByKey map[string]time.Time // "ip:category"
	lastAlertID    map[string]string
	countByKey     map[string]int
}

func newWebPathProbeState() *webPathProbeState {
	return &webPathProbeState{
		lastAlertByKey: make(map[string]time.Time),
		lastAlertID:    make(map[string]string),
		countByKey:     make(map[string]int),
	}
}

func getWebPathProbeState(ctx *context.DetectionContext) *webPathProbeState {
	if v, ok := ctx.GetPrivate("web_path_probe"); ok {
		return v.(*webPathProbeState)
	}
	s := newWebPathProbeState()
	ctx.SetPrivate("web_path_probe", s)
	return s
}

// ── Evaluate ───────────────────────────────────────────────────────────────

func (r *WebPathProbeRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {
	ip := event.SourceIP
	now := event.Timestamp

	if ip == "" || event.Command == "" {
		return nil
	}

	// Extract URI from "METHOD /uri" stored in Command
	parts := strings.SplitN(event.Command, " ", 2)
	if len(parts) < 2 {
		return nil
	}
	uri := strings.ToLower(parts[1])

	// Find which attack category matches
	var matched *probeCategory
	for i := range probeCategories {
		cat := &probeCategories[i]
		for _, pat := range cat.Patterns {
			if strings.Contains(uri, pat) {
				matched = cat
				break
			}
		}
		if matched != nil {
			break
		}
	}

	if matched == nil {
		// HTTP_PROBE was set by scanner UA — handled by WebScannerUARule
		return nil
	}

	s := getWebPathProbeState(ctx)
	key := ip + ":" + matched.Name
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

	s.countByKey[key] = 1
	alert := model.NewAlert(
		matched.Name+" Probe",
		matched.Severity,
		"web-attack",
		fmt.Sprintf("IP %s: %s pattern in URI: %s (%d requests)", ip, matched.Name, parts[1], count),
		event,
		count,
	)
	s.lastAlertByKey[key] = now
	s.lastAlertID[key] = alert.ID

	return []*model.Alert{alert}
}
