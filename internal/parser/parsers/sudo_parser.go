package parsers

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

var sudoCommandRegex = regexp.MustCompile(`COMMAND=(.+)$`)
var sudoUserKVRegex = regexp.MustCompile(`user=([a-zA-Z0-9_-]+)`)
var sudoUserRegex = regexp.MustCompile(`^(\w+)\s:`)
var sudoAttemptRegex = regexp.MustCompile(`(\d+) incorrect password attempts`)
var sudoRuserRegex = regexp.MustCompile(`ruser=([a-zA-Z0-9_-]+)`)

func SUDOParser(event *model.NormalizedEvent) *model.NormalizedEvent {

	msg := event.Message

	// SUDO COMMAND EXECUTION
	if strings.Contains(msg, "COMMAND=") {

		event.EventType = "SUDO_EXEC"
		event.Username = extractSudoUser(msg)
		event.Command = extractSudoCommand(msg)
		event.EventCount = extractAttemptCount(msg)

		return event
	}

	// SUDO AUTH FAILURE
	if strings.Contains(msg, "authentication failure") ||
		strings.Contains(msg, "incorrect password") {

		event.EventType = "SUDO_FAIL"
		event.Username = extractSudoUserFromKV(msg)

		return event
	}

	// SESSION START
	if strings.Contains(msg, "session opened for user root") {

		event.EventType = "SUDO_SESSION_START"
		event.Username = extractRUser(msg)

		return event
	}

	// SESSION END
	if strings.Contains(msg, "session closed for user root") {

		event.EventType = "SUDO_SESSION_END"
		event.Username = extractSessionUser(msg)

		return event
	}

	return event
}

func extractSudoUser(message string) string {
	matches := sudoUserRegex.FindStringSubmatch(message)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func extractSudoCommand(message string) string {
	matches := sudoCommandRegex.FindStringSubmatch(message)
	if len(matches) == 2 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

func extractSessionUser(message string) string {
	// for: session opened for user root
	parts := strings.Split(message, " ")
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "user" {
			return parts[i+1]
		}
	}
	return ""
}

func extractSudoUserFromKV(message string) string {
	matches := sudoUserKVRegex.FindStringSubmatch(message)
	if len(matches) == 2 {
		return matches[1]
	}
	return ""
}

func extractAttemptCount(message string) int {
	matches := sudoAttemptRegex.FindStringSubmatch(message)
	if len(matches) == 2 {
		n, _ := strconv.Atoi(matches[1])
		return n
	}
	return 1
}

func extractRUser(message string) string {
	matches := sudoRuserRegex.FindStringSubmatch(message)
	if len(matches) == 2 {
		return matches[1]
	}
	return ""
}
