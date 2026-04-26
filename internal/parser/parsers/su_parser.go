package parsers

import (
	"strings"

	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// SUParser handles log lines emitted by the "su" program.
//
// Recognised patterns:
//
//	FAILED su for root by alice
//	Successful su for root by alice
//	pam_unix(su:auth): authentication failure; ... ruser=alice ... user=root
//	+ /dev/pts/0 alice:root
func SUParser(event *model.NormalizedEvent) *model.NormalizedEvent {
	msg := event.Message
	msgLower := strings.ToLower(msg)

	switch {
	// "FAILED su for root by alice"
	case strings.HasPrefix(msg, "FAILED su for"):
		event.EventType = "SU_FAIL"
		event.Command = extractSUTarget(msg)     // target account (root)
		event.Username = extractSUInitiator(msg) // who tried (alice)

	// "Successful su for root by alice"
	case strings.HasPrefix(msgLower, "successful su for"):
		event.EventType = "SU_SUCCESS"
		event.Command = extractSUTarget(msg)
		event.Username = extractSUInitiator(msg)

	// PAM failure: "authentication failure; ... ruser=alice ... user=root"
	case strings.Contains(msg, "authentication failure") && strings.Contains(msg, "ruser="):
		event.EventType = "SU_FAIL"
		event.Username = extractSURUser(msg)     // ruser=alice
		event.Command = extractSUTargetUser(msg) // user=root (target)

	case strings.Contains(msgLower, "session opened for user"):
		event.EventType = "SU_SUCCESS"
		event.Username = extractSURUser(msg)
		event.Command = extractSUTargetUser(msg)

	case strings.HasPrefix(msg, "FAILED SU"):
		event.EventType = "SU_FAIL"
		event.Command = extractTargetFromParen(msg)
		event.Username = extractUserBeforeOn(msg)

	case strings.Contains(msgLower, "session closed for user"):
		event.EventType = "SU_SESSION_CLOSE"
		event.Command = extractSUTargetUser(msg)

	// Successful PAM su: "+ /dev/pts/0 alice:root"
	case strings.HasPrefix(msg, "+ "):
		parts := strings.Fields(msg)
		for _, p := range parts {
			if strings.Contains(p, ":") {
				pair := strings.SplitN(p, ":", 2)
				if len(pair) == 2 && pair[0] != "" && pair[1] != "" {
					event.EventType = "SU_SUCCESS"
					event.Username = pair[0]
					event.Command = pair[1]
				}
				break
			}
		}
	}

	return event
}

// extractSUInitiator returns the initiating user from su messages.
// e.g. "FAILED su for root by alice" → "alice"
func extractSUInitiator(msg string) string {
	parts := strings.Fields(msg)
	for i, p := range parts {
		if p == "by" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// extractSUTarget returns the target account from su messages.
// e.g. "FAILED su for root by alice" → "root"
func extractSUTarget(msg string) string {
	parts := strings.Fields(msg)
	for i, p := range parts {
		if p == "for" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func extractSURUser(msg string) string {
	if idx := strings.Index(msg, "ruser="); idx != -1 {
		start := idx + len("ruser=")
		end := start

		for end < len(msg) && msg[end] != ' ' && msg[end] != ';' {
			end++
		}
		return stripParentheses(msg[start:end])
	}

	parts := strings.Fields(msg)
	for i, p := range parts {
		if p == "by" && i+1 < len(parts) {
			return stripParentheses(parts[i+1])
		}
	}

	return ""
}

// Handles:
//
//	user=root
//	for root
//	user root (session logs)
func extractSUTargetUser(msg string) string {
	if idx := strings.Index(msg, "user="); idx != -1 {
		start := idx + len("user=")
		end := start

		for end < len(msg) && msg[end] != ' ' && msg[end] != ';' {
			end++
		}
		return stripParentheses(msg[start:end])
	}

	parts := strings.Fields(msg)

	for i, p := range parts {
		if p == "for" && i+1 < len(parts) {
			return stripParentheses(parts[i+1])
		}
	}

	for i, p := range parts {
		if p == "user" && i+1 < len(parts) {
			return stripParentheses(parts[i+1])
		}
	}

	return ""
}

func stripParentheses(value string) string {
	if idx := strings.Index(value, "("); idx != -1 {
		return value[:idx]
	}
	return value
}

func extractTargetFromParen(msg string) string {
	start := strings.Index(msg, "(to ")
	if start == -1 {
		return ""
	}
	start += len("(to ")

	end := strings.Index(msg[start:], ")")
	if end == -1 {
		return ""
	}

	return msg[start : start+end]
}

func extractUserBeforeOn(msg string) string {
	parts := strings.Fields(msg)
	for i, p := range parts {
		if p == "on" && i-1 >= 0 {
			return parts[i-1]
		}
	}
	return ""
}
