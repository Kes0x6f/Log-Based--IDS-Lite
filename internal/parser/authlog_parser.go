package parser

import (
	"bufio"
	"errors"
	"os"
	"regexp"

	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
	"github.com/Kes0x6f/Log-Based--IDS/internal/parsetimestamp"
)

var headerRegex = regexp.MustCompile(
	`^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([a-zA-Z0-9_-]+)(?:\[\d+\])?:\s+(.*)$`,
)

func AuthLogParser(f *os.File) []*model.NormalizedEvent {
	scanner := bufio.NewScanner(f)

	var logs []*model.NormalizedEvent

	for scanner.Scan() {
		line, err := ParseLine(scanner.Text())

		if err != nil {
			continue
		}
		logs = append(logs, line)

	}
	return logs
}

func ParseLine(line string) (*model.NormalizedEvent, error) {

	matches := headerRegex.FindStringSubmatch(line)

	if matches == nil {
		return nil, errors.New("header parse failed")
	}

	timestamp, err := parsetimestamp.ParseTimeStamp(matches[1])

	if err != nil {
		return nil, err
	}

	event := &model.NormalizedEvent{
		Timestamp: timestamp,
		Host:      matches[2],
		Program:   matches[3],
		Message:   matches[4],
		RawLine:   line,
	}

	return event, err
}
