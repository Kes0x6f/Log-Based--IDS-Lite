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
	//remote access
	"sshd": parsers.SSHParser,

	//escalated privilage abuse via sudo
	"sudo": parsers.SUDOParser,

	// privilege escalation via su
	"su": parsers.SUParser,

	// account / group / credential events
	"useradd": parsers.UserAddParser,
	"userdel": parsers.UserDelParser,
	"usermod": parsers.UserModParser,
	"passwd":  parsers.PasswdParser,

	// ── ufw.log + kern.log
	// KernParser delegates UFW lines to UFWParser internally.
	"kernel": parsers.KernParser,
}

type Parser interface {
	Parse(filePath string) ([]*model.NormalizedEvent, error)
}

func ParserWorker(input <-chan collector.RawLog, output chan<- *model.NormalizedEvent) {

	for log := range input {

		line := strings.TrimSpace(log.Message)

		// ── Fast path: raw audit.log lines ──────────────────────────────────
		// Raw audit.log records start with "type=" and have no syslog header.
		// The source tag "audit" is assigned by the FileCollector for this file.
		if log.Source == "audit" && strings.HasPrefix(line, "type=") {
			event := parsers.ParseRawAuditLine(line, log.Source)
			if event != nil && event.EventType != "" {
				fmt.Println(event)
				output <- event
			}
			continue
		}

		// ── Fast path: Apache / Nginx access log lines ───────────────────────
		// Combined Log Format starts with an IP address, not a syslog timestamp.
		// Source tags "apache2" and "nginx" both arrive here.
		if log.Source == "apache2" || log.Source == "nginx" {
			event := parsers.ParseWebLogLine(line, log.Source)
			if event != nil && event.EventType != "" {
				fmt.Println(event)
				output <- event
			}
			continue
		}

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
			// ISO format
			timestamp, err = time.Parse(time.RFC3339Nano, timestampStr)
		} else {
			// syslog format
			timestamp, err = parsetimestamp.ParseTimeStamp(timestampStr)
		}

		if err != nil {
			continue
		}

		if err != nil {
			fmt.Println("error in timestamp")
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
