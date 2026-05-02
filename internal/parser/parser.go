package parser

import (
	"fmt"
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

	for log := range input {

		line := strings.TrimSpace(log.Message)
		if line == "" {
			continue
		}

		// ── Fast path: raw audit.log lines ──────────────────────────────────
		// audit.log records start with "type=" and carry no syslog header.
		if log.Source == "audit" && strings.HasPrefix(line, "type=") {
			event := parsers.ParseRawAuditLine(line, log.Source)
			if event != nil && event.EventType != "" {
				output <- event
			}
			continue
		}

		// ── Fast path: Apache2 / Nginx access logs ───────────────────────────
		// Combined Log Format has no syslog header; the header regex would not
		// match and the line would be silently dropped without this branch.
		if log.Source == "apache2" || log.Source == "nginx" {
			event := parsers.ParseWebLogLine(line, log.Source)
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
			fmt.Println("timestamp parse error:", err)
			continue
		}

		event := &model.NormalizedEvent{
			Timestamp:  timestamp,
			Host:       matches[2],
			LogSource:  log.Source,
			Program:    matches[3],
			Message:    matches[4],
			RawLine:    log.Message,
			EventCount: 1,
		}

		if parser, ok := programParsers[event.Program]; ok {
			parser(event)
		}
		fmt.Println(event)

		output <- event
	}
}
