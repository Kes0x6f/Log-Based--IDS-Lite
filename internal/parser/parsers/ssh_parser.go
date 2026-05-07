package parsers

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

var ipPortRegex = regexp.MustCompile(`(\S+) port (\d+)`)
var repeatRegex = regexp.MustCompile(`message repeated (\d+) times`)
var pamRepeatRegex = regexp.MustCompile(`(\d+) more authentication failure(s)?`)

// authMethodRe matches the auth method in Accepted/Failed lines.
// e.g. "Failed password for root" → "password"
//
//	"Accepted publickey for alice" → "publickey"
var authMethodRe = regexp.MustCompile(`(?:Accepted|Failed)\s+(\S+)\s+for`)

func SSHParser(event *model.NormalizedEvent) *model.NormalizedEvent {
	message := event.Message
	switch {

	// "message repeated N times: [ Failed password for root from 1.2.3.4 port 22]"
	case strings.Contains(message, "message repeated"):
		event.EventType = "SSH_FAILED"
		event.Username = extractUsername(message)
		event.SourceIP, event.Port = extractIPPort(message)
		event.EventCount = extractRepeatCount(message)
		// AuthMethod is its own field — not Command.
		event.AuthMethod = extractAuthMethod(message)

	// "Failed password for root from 1.2.3.4 port 22"
	// "Failed password for invalid user bob from 1.2.3.4 port 22"
	case strings.Contains(message, "Failed") && strings.Contains(message, "for"):
		event.EventType = "SSH_FAILED"
		if strings.Contains(message, "invalid user") {
			event.EventType = "SSH_INVALID_USER"
		}
		event.Username = extractUsername(message)
		event.SourceIP, event.Port = extractIPPort(message)
		event.AuthMethod = extractAuthMethod(message)

	// "Accepted password for alice from 1.2.3.4 port 22"
	// "Accepted publickey for alice from 1.2.3.4 port 22"
	case strings.Contains(message, "Accepted password") || strings.Contains(message, "Accepted publickey"):
		event.EventType = "SSH_SUCCESS"
		event.Username = extractUsername(message)
		event.SourceIP, event.Port = extractIPPort(message)
		event.AuthMethod = extractAuthMethod(message)

	// "Invalid user bob from 1.2.3.4 port 22"
	case strings.HasPrefix(message, "Invalid user"):
		event.EventType = "SSH_INVALID_USER"
		event.Username = extractInvalidUser(message)
		event.SourceIP, event.Port = extractIPPort(message)

	// "error: maximum authentication attempts exceeded for root from 1.2.3.4 port 22 ssh2"
	case strings.Contains(message, "maximum authentication attempts exceeded"):
		event.EventType = "SSH_MAX_AUTH_ATTEMPTS"
		event.Username = extractUsername(message)
		event.SourceIP, event.Port = extractIPPort(message)
		event.AuthMethod = extractAuthMethod(message)

	// "Disconnected from authenticating user root 1.2.3.4 port 22"
	case strings.Contains(message, "Disconnected from"):
		event.EventType = "SSH_DISCONNECT"
		event.Username = extractUsername(message)
		event.SourceIP, event.Port = extractIPPort(message)

	// "Connection closed by 1.2.3.4 port 22"
	case strings.Contains(message, "Connection closed"):
		event.EventType = "SSH_DISCONNECT"
		event.Username = extractUsername(message)
		event.SourceIP, event.Port = extractIPPort(message)

	// PAM: "authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.2.3.4 user=root"
	case strings.Contains(message, "authentication failure"):
		event.EventType = "SSH_FAILED"
		event.SourceIP = extractIPFromRhost(message)
		event.Username = extractUserFromPAM(message)
		event.EventCount = extractPAMRepeat(message)

	// fallback — extract what we can
	default:
		event.Username = extractUsername(message)
		event.SourceIP, event.Port = extractIPPort(message)
	}
	return event
}

// extractAuthMethod returns the SSH authentication mechanism from a log line.
// Returns "password", "publickey", "keyboard-interactive", etc., or "".
func extractAuthMethod(message string) string {
	if m := authMethodRe.FindStringSubmatch(message); len(m) == 2 {
		return m[1]
	}
	return ""
}

func extractIPPort(message string) (string, string) {
	matches := ipPortRegex.FindStringSubmatch(message)
	if len(matches) == 3 {
		return matches[1], matches[2]
	}
	return "", ""
}

func extractUsername(message string) string {
	parts := strings.Split(message, " ")
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "for" {
			if parts[i+1] == "invalid" && i+3 < len(parts) {
				return parts[i+3]
			}
			return parts[i+1]
		}
		if parts[i] == "user" {
			return parts[i+1]
		}
	}
	return ""
}

func extractInvalidUser(message string) string {
	parts := strings.Split(message, " ")
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}

func extractIPFromRhost(message string) string {
	parts := strings.Split(message, " ")
	for _, p := range parts {
		if strings.HasPrefix(p, "rhost=") {
			return strings.TrimPrefix(p, "rhost=")
		}
	}
	return ""
}

func extractUserFromPAM(message string) string {
	parts := strings.Split(message, " ")
	for _, p := range parts {
		if strings.HasPrefix(p, "user=") {
			return strings.TrimPrefix(p, "user=")
		}
	}
	return ""
}

func extractRepeatCount(message string) int {
	matches := repeatRegex.FindStringSubmatch(message)
	if len(matches) == 2 {
		n, _ := strconv.Atoi(matches[1])
		return n + 1
	}
	return 1
}

func extractPAMRepeat(message string) int {
	matches := pamRepeatRegex.FindStringSubmatch(message)
	if len(matches) == 2 {
		n, _ := strconv.Atoi(matches[1])
		return n
	}
	return 1
}
