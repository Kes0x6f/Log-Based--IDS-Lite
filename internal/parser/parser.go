package parser

import (
	"fmt"
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

var programParsers = map[string]func(*model.NormalizedEvent) *model.NormalizedEvent{
	"sshd": parsers.SSHParser,
}

type Parser interface {
	Parse(filePath string) ([]*model.NormalizedEvent, error)
}

func ParserWorker(input <-chan collector.RawLog, output chan<- *model.NormalizedEvent) {

	for log := range input {

		line := strings.TrimSpace(log.Message)
		matches := headerRegex.FindStringSubmatch(line)

		if matches == nil {
			fmt.Println("error in regex")
			continue
		}

		timestamp, err := parsetimestamp.ParseTimeStamp(matches[1])

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
		}

		if parser, ok := programParsers[event.Program]; ok {
			parser(event)
		}
		fmt.Println(event)

		output <- event
	}

}
