package authparser

import (
	"regexp"
	"strings"

	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

var ipPortRegex = regexp.MustCompile(`from (\S+) port (\d+)`)

func SSHParser(event *model.NormalizedEvent) *model.NormalizedEvent {
	message := event.Message
	//failed password
	switch {
	case strings.Contains(message, "Failed password"):
		event.EventType = "SSH_FAILED"
		// Handle "invalid user" variant
		if strings.Contains(message, "invalid user") {
			event.EventType = "SSH_INVALID_USER"
		}
		event.Username = extractUsername(message)
		event.SourceIP, event.Port = extractIPPort(message)

	//accepted login
	case strings.Contains(message, "Accepted password") || strings.Contains(message, "Accepted publickey"):

		event.EventType = "SSH_SUCCESS"
		event.Username = extractUsername(message)
		event.SourceIP, event.Port = extractIPPort(message)

	//invalid user
	case strings.HasPrefix(message, "Invalid user"):

		event.EventType = "SSH_INVALID_USER"
		event.Username = extractInvalidUser(message)
		event.SourceIP, event.Port = extractIPPort(message)

	//Max authenticaiton attempts
	case strings.Contains(message, "maximum authentication attempts exceeded"):
		event.EventType = "SSH_MAX_AUTH_ATTEMPTS"
		event.Username = extractUsername(message)
		event.SourceIP, event.Port = extractIPPort(message)

	//disconnect
	case strings.Contains(message, "Disconnected from"):
		event.EventType = "SSH_DISCONNECT"
		event.Username = extractUsername(message)
		event.SourceIP, event.Port = extractIPPort(message)

	//for events not mentioned
	default:
		event.Username = extractUsername(message)
		event.SourceIP, event.Port = extractIPPort(message)
	}
	return event
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
			// Handle: for invalid user admin
			if parts[i+1] == "invalid" && i+3 < len(parts) {
				return parts[i+3]
			}
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
