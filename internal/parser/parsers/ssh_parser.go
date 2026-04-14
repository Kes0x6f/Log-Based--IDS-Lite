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

func SSHParser(event *model.NormalizedEvent) *model.NormalizedEvent {
	message := event.Message
	//failed password
	switch {
	//repeated message
	case strings.Contains(message, "message repeated"):
		event.EventType = "SSH_FAILED"
		event.Username = extractUsername(message)
		event.SourceIP, event.Port = extractIPPort(message)
		event.EventCount = extractRepeatCount(message)

	case strings.Contains(message, "Failed") && strings.Contains(message, "for"):
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

	//connection closed
	case strings.Contains(message, "Connection closed"):
		event.EventType = "SSH_DISCONNECT"
		event.Username = extractUsername(message)
		event.SourceIP, event.Port = extractIPPort(message)

	//PAM authentication failure
	case strings.Contains(message, "authentication failure"):
		event.EventType = "SSH_FAILED"
		event.SourceIP = extractIPFromRhost(message)
		event.Username = extractUserFromPAM(message)
		event.EventCount = extractPAMRepeat(message)

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
		// Case 1: "for <user>"
		if parts[i] == "for" {
			// Handle: for invalid user admin
			if parts[i+1] == "invalid" && i+3 < len(parts) {
				return parts[i+3]
			}
			return parts[i+1]
		}

		// Case 2: "user <username>"
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
	// look for: rhost=IP
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
		return n + 1 // include original event
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
