package rule

import (
	"fmt"
	"strings"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// WebScannerUARule fires when an HTTP request arrives with a user-agent
// that belongs to a known security scanner or attack tool.
//
// Scanner UAs are detected by the parser (web_parser.go) before this rule
// runs. The rule's job is to produce a named, categorised, cooldown-deduped
// alert rather than one alert per request.
//
// A per-(IP, UA-substring) cooldown prevents floods from automated tools
// that send thousands of requests per minute, while still alerting on the
// first hit and updating the count during cooldown.
type WebScannerUARule struct {
	Cooldown time.Duration
}

func NewWebScannerUARule() *WebScannerUARule {
	return &WebScannerUARule{
		Cooldown: 10 * time.Minute,
	}
}

func (r *WebScannerUARule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:  "web",
		Program:    "httpd",
		EventTypes: []string{"HTTP_PROBE"},
	}
}

// ── Private state ──────────────────────────────────────────────────────────

type webScannerUAState struct {
	lastAlertByKey map[string]time.Time // "ip:ua-signature"
	lastAlertID    map[string]string
	countByKey     map[string]int
}

func newWebScannerUAState() *webScannerUAState {
	return &webScannerUAState{
		lastAlertByKey: make(map[string]time.Time),
		lastAlertID:    make(map[string]string),
		countByKey:     make(map[string]int),
	}
}

func getWebScannerUAState(ctx *context.DetectionContext) *webScannerUAState {
	if v, ok := ctx.GetPrivate("web_scanner_ua"); ok {
		return v.(*webScannerUAState)
	}
	s := newWebScannerUAState()
	ctx.SetPrivate("web_scanner_ua", s)
	return s
}

// knownScannerLabels maps UA substrings to human-readable tool names
// for clear alert messages.
var knownScannerLabels = map[string]string{
	"nikto":           "Nikto",
	"sqlmap":          "sqlmap",
	"masscan":         "Masscan",
	"dirbuster":       "DirBuster",
	"gobuster":        "Gobuster",
	"wfuzz":           "WFuzz",
	"acunetix":        "Acunetix",
	"nessus":          "Nessus",
	"openvas":         "OpenVAS",
	"w3af":            "w3af",
	"arachni":         "Arachni",
	"nmap":            "Nmap NSE",
	"zgrab":           "ZGrab",
	"nuclei":          "Nuclei",
	"hydra":           "Hydra",
	"medusa":          "Medusa",
	"burpsuite":       "Burp Suite",
	"burp ":           "Burp Suite",
	"libwww-perl":     "libwww-perl",
	"python-requests": "python-requests",
	"go-http-client":  "Go HTTP client",
	"java/":           "Java HTTP client",
	"httpclient":      "HTTPClient",
	"scanner":         "generic scanner",
	"fuzzer":          "fuzzer",
	"fuzz":            "fuzzer",
}

// ── Evaluate ───────────────────────────────────────────────────────────────

func (r *WebScannerUARule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {
	ua := strings.ToLower(event.Message)
	ip := event.SourceIP
	now := event.Timestamp

	if ua == "" || ip == "" {
		return nil
	}

	// Identify which scanner this is
	toolName := ""
	matchedSig := ""
	for sig, label := range knownScannerLabels {
		if strings.Contains(ua, sig) {
			toolName = label
			matchedSig = sig
			break
		}
	}
	if toolName == "" {
		return nil
	}

	s := getWebScannerUAState(ctx)
	key := ip + ":" + matchedSig
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
		"Web Scanner Detected",
		model.SeverityHigh,
		"reconnaissance",
		fmt.Sprintf("Scanner tool %s detected from IP %s (%d requests)", toolName, ip, count),
		event,
		count,
	)
	s.lastAlertByKey[key] = now
	s.lastAlertID[key] = alert.ID

	return []*model.Alert{alert}
}
