package parsers

import (
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// Combined Log Format (Apache / Nginx default access log):
//
//	127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /path HTTP/1.1" 200 2326 "http://ref/" "Mozilla/5.0"
//
// NormalizedEvent field mapping:
//
//	SourceIP  → client IP
//	Command   → "METHOD /raw-uri"  (keeps the raw URI for human readability)
//	Port      → HTTP status code string ("404", "200", …)
//	Username  → auth user field (or "-" when unauthenticated)
//	Message   → user-agent string
//	Program   → "httpd"   (same for both Apache and Nginx)
//	LogSource → "web"     (set by ParseWebLogLine regardless of source tag)

var combinedLogRe = regexp.MustCompile(
	`^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)[^"]*"\s+(\d{3})\s+\S+` +
		`(?:\s+"[^"]*"\s+"([^"]*)")?`,
)

const webTimestampLayout = "02/Jan/2006:15:04:05 -0700"

// ParseWebLogLine parses one line from an Apache or Nginx access log.
// Returns nil when the line does not match the Combined Log Format.
// The source argument is informational only — all web events are emitted
// with LogSource="web" and Program="httpd" so the same rule set fires
// regardless of which server produced the log.
func ParseWebLogLine(line, _ string) *model.NormalizedEvent {
	m := combinedLogRe.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return nil
	}

	clientIP := m[1]
	authUser := m[2]
	rawTS := m[3]
	method := strings.ToUpper(m[4])
	rawURI := m[5]
	statusCode := m[6]
	userAgent := m[7]

	ts, err := time.Parse(webTimestampLayout, rawTS)
	if err != nil {
		ts = time.Now()
	}

	// URL-decode and lower-case for pattern matching
	decodedURI, err := url.QueryUnescape(rawURI)
	if err != nil {
		decodedURI = rawURI
	}
	decodedURI = strings.ToLower(decodedURI)

	eventType := classifyWebEvent(method, decodedURI, statusCode, strings.ToLower(userAgent))

	return &model.NormalizedEvent{
		Timestamp:  ts,
		LogSource:  "web",
		Program:    "httpd",
		EventType:  eventType,
		SourceIP:   clientIP,
		Username:   authUser,
		Command:    method + " " + rawURI,
		Port:       statusCode,
		Message:    userAgent,
		RawLine:    line,
		EventCount: 1,
	}
}

// ── Classification ──────────────────────────────────────────────────────────
// Priority: PROBE > AUTH_FAIL > 404 > METHOD > REQUEST

func classifyWebEvent(method, decodedURI, status, uaLower string) string {
	if isScannerUA(uaLower) {
		return "HTTP_PROBE"
	}
	if hasAttackPattern(decodedURI) {
		return "HTTP_PROBE"
	}
	if status == "401" || (status == "403" && method == "POST") {
		return "HTTP_AUTH_FAIL"
	}
	if status == "404" {
		return "HTTP_404"
	}
	if isUnusualMethod(method) {
		return "HTTP_METHOD"
	}
	return "HTTP_REQUEST"
}

// ── Scanner user-agent signatures ──────────────────────────────────────────

var scannerUASignatures = []string{
	"nikto",
	"sqlmap",
	"masscan",
	"dirbuster",
	"gobuster",
	"wfuzz",
	"acunetix",
	"nessus",
	"openvas",
	"w3af",
	"arachni",
	"nmap",
	"zgrab",
	"nuclei",
	"hydra",
	"medusa",
	"burpsuite",
	"burp ",
	"libwww-perl",
	"python-requests",
	"go-http-client",
	"java/",
	"httpclient",
	"scanner",
	"fuzzer",
	"fuzz",
}

func isScannerUA(ua string) bool {
	for _, sig := range scannerUASignatures {
		if strings.Contains(ua, sig) {
			return true
		}
	}
	return false
}

// ── Attack patterns in URI ──────────────────────────────────────────────────
// All evaluated against the URL-decoded, lowercased URI.

var attackPatterns = []string{
	// Directory traversal
	"../", "..\\", "%2e%2e", "..%2f", "%2e%2e%2f", "%2e%2e%5c", "....//",

	// Common traversal targets
	"/etc/passwd", "/etc/shadow", "wp-config.php", ".env",
	"/.git/", "/.svn/", "web.config",

	// SQL injection
	"union select", "union+select", "' or '", "'or'1'", "or 1=1",
	"; drop ", ";drop ", "information_schema", "xp_cmdshell",
	"waitfor delay", "sleep(", "benchmark(", "load_file(", "into outfile",

	// XSS
	"<script", "javascript:", "onerror=", "onload=", "onmouseover=",
	"onfocus=", "alert(", "document.cookie", "document.write(", "fromcharcode",

	// RCE / shell injection
	";cat ", "|cat ", "|id ", "|whoami", "$(id)", "`id`",
	"/bin/bash", "/bin/sh", "cmd.exe", "powershell",

	// LFI / RFI
	"php://input", "php://filter", "data://", "expect://", "file://",
}

func hasAttackPattern(uri string) bool {
	for _, pat := range attackPatterns {
		if strings.Contains(uri, pat) {
			return true
		}
	}
	return false
}

// ── Unusual HTTP methods ────────────────────────────────────────────────────

var unusualMethods = map[string]bool{
	"TRACE":   true, // XST attack vector
	"CONNECT": true, // proxy tunnel abuse
	"OPTIONS": true, // information disclosure
	"PUT":     true,
	"DELETE":  true,
	"PATCH":   true,
}

func isUnusualMethod(method string) bool {
	return unusualMethods[method]
}
