package parser

import (
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/collector"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
	"github.com/Kes0x6f/Log-Based--IDS/internal/parser/parsers"
	"github.com/Kes0x6f/Log-Based--IDS/internal/parsetimestamp"
)

var headerRegex = regexp.MustCompile(
	`^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([a-zA-Z0-9_-]+)(?:\[\d+\])?:\s+(.*)$`,
)

var isoHeaderRegex = regexp.MustCompile(
	`^(\d{4}-\d{2}-\d{2}T[\d:.+-]+)\s+(\S+)\s+([a-zA-Z0-9_-]+)(?:\[\d+\])?:\s+(.*)$`,
)

var programParsers = map[string]func(*model.NormalizedEvent) *model.NormalizedEvent{
	// Remote access
	"sshd": parsers.SSHParser,

	// Privilege escalation
	"sudo": parsers.SUDOParser,
	"su":   parsers.SUParser,

	// Account / group / credential events
	"useradd": parsers.UserAddParser,
	"userdel": parsers.UserDelParser,
	"usermod": parsers.UserModParser,
	"passwd":  parsers.PasswdParser,

	// Kernel (delegates UFW lines to UFWParser internally)
	"kernel": parsers.KernParser,
}

type Parser interface {
	Parse(filePath string) ([]*model.NormalizedEvent, error)
}

func ParserWorker(input <-chan collector.RawLog, output chan<- *model.NormalizedEvent) {

	for rawLog := range input {

		line := strings.TrimSpace(rawLog.Message)
		if line == "" {
			continue
		}

		// ── Fast path: raw audit.log lines ──────────────────────────────────
		// audit.log records start with "type=" and carry no syslog header.
		if rawLog.Source == "audit" && strings.HasPrefix(line, "type=") {
			event := parsers.ParseRawAuditLine(line, rawLog.Source)
			if event != nil && event.EventType != "" {
				output <- event
			}
			continue
		}

		// ── Fast path: Apache2 / Nginx access logs ───────────────────────────
		// Combined Log Format has no syslog header; the header regex would not
		// match and the line would be silently dropped without this branch.
		if rawLog.Source == "apache2" || rawLog.Source == "nginx" {
			event := parsers.ParseWebLogLine(line, rawLog.Source)
			if event != nil && event.EventType != "" {
				output <- event
			}
			continue
		}

		// ── Standard syslog header path ──────────────────────────────────────
		var matches []string
		var timestampStr string

		matches = isoHeaderRegex.FindStringSubmatch(line)
		if matches != nil {
			timestampStr = matches[1]
		} else {
			matches = headerRegex.FindStringSubmatch(line)
			if matches != nil {
				timestampStr = matches[1]
			}
		}

		if matches == nil {
			continue
		}

		var timestamp time.Time
		var err error

		if strings.Contains(timestampStr, "T") {
			timestamp, err = time.Parse(time.RFC3339Nano, timestampStr)
		} else {
			timestamp, err = parsetimestamp.ParseTimeStamp(timestampStr)
		}

		if err != nil {
			log.Printf("ParserWorker: timestamp parse error: %v", err)
			continue
		}

		event := &model.NormalizedEvent{
			Timestamp:  timestamp,
			Host:       matches[2],
			LogSource:  rawLog.Source,
			Program:    matches[3],
			Message:    matches[4],
			RawLine:    rawLog.Message,
			EventCount: 1,
		}

		if parser, ok := programParsers[event.Program]; ok {
			parser(event)
		}

		// Skip events the parser did not classify — they carry no EventType
		// and would waste engine work without matching any rule.
		if event.EventType == "" {
			continue
		}

		output <- event
	}
}
