package parser

import (
	"fmt"
	"time"
	"regexp"
	"strings"

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
	"sshd": parsers.SSHParser,
}

type Parser interface {
	Parse(filePath string) ([]*model.NormalizedEvent, error)
}

func ParserWorker(input <-chan collector.RawLog, output chan<- *model.NormalizedEvent) {

	for log := range input {

		line := strings.TrimSpace(log.Message)
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
			Timestamp: timestamp,
			Host:      matches[2],
			LogSource: log.Source,
			Program:   matches[3],
			Message:   matches[4],
			RawLine:   log.Message,
			EventCount: 1,
		}

		if parser, ok := programParsers[event.Program]; ok {
			parser(event)
		}
		fmt.Println(event)

		output <- event
	}

}
