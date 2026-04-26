package parsers

import (
	"strings"

	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// UFWParser handles kernel log lines produced by ufw.
//
// Recognised line shapes (all start with an optional kernel timestamp):
//
//	[12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=5.6.7.8 ... PROTO=TCP SPT=12345 DPT=22 ...
//	[12345.678901] [UFW ALLOW] IN=eth0 OUT= ... SRC=1.2.3.4 ... DPT=80 ...
//
// Direction:
//
//	IN non-empty, OUT empty  → inbound  → FW_BLOCK
//	OUT non-empty, IN empty  → outbound → FW_BLOCK_OUT
//
// Fields stored in NormalizedEvent:
//
//	SourceIP → SRC=
//	Port     → DPT= (destination port being blocked/allowed)
//	Command  → PROTO= (TCP / UDP / ICMP …)
func UFWParser(event *model.NormalizedEvent) *model.NormalizedEvent {
	msg := event.Message

	// Fast exit: not a UFW log line
	if !strings.Contains(msg, "[UFW ") {
		return event
	}

	switch {
	case strings.Contains(msg, "[UFW BLOCK]"):
		in := ufwExtractKV(msg, "IN")
		out := ufwExtractKV(msg, "OUT")

		if out != "" && in == "" {
			event.EventType = "FW_BLOCK_OUT"
		} else {
			event.EventType = "FW_BLOCK"
		}
		event.SourceIP = ufwExtractKV(msg, "SRC")
		event.Port = ufwExtractKV(msg, "DPT")
		event.Command = ufwExtractKV(msg, "PROTO")

	case strings.Contains(msg, "[UFW ALLOW]"):
		event.EventType = "FW_ALLOW"
		event.SourceIP = ufwExtractKV(msg, "SRC")
		event.Port = ufwExtractKV(msg, "DPT")
		event.Command = ufwExtractKV(msg, "PROTO")

	case strings.Contains(msg, "[UFW AUDIT]"):
		event.EventType = "FW_AUDIT"
		event.SourceIP = ufwExtractKV(msg, "SRC")
		event.Port = ufwExtractKV(msg, "DPT")
	}

	return event
}

// ufwExtractKV extracts the value from a "KEY=value" token in a UFW log line.
// Returns empty string when the key is absent or when KEY= is immediately
// followed by whitespace (e.g. "OUT= " means no outbound interface).
func ufwExtractKV(msg, key string) string {
	prefix := key + "="
	fields := strings.Fields(msg)
	for _, f := range fields {
		if strings.HasPrefix(f, prefix) {
			v := strings.TrimPrefix(f, prefix)
			return v
		}
	}
	return ""
}
