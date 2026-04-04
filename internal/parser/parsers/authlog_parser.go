package parsers

import (
	"bufio"
	"errors"
	"log"
	"regexp"

	"github.com/Kes0x6f/Log-Based--IDS/internal/filehandler"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
	"github.com/Kes0x6f/Log-Based--IDS/internal/parsetimestamp"
)

type AuthParser struct{}

func New() *AuthParser {
	return &AuthParser{}
}

var headerRegex = regexp.MustCompile(
	`^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([a-zA-Z0-9_-]+)(?:\[\d+\])?:\s+(.*)$`,
)

func (p *AuthParser) Parse(filePath string) ([]*model.NormalizedEvent, error) {
	file, err := filehandler.OpenFile(filePath)

	if err != nil {
		log.Fatal(err)
	}

	scanner := bufio.NewScanner(file)

	var logs []*model.NormalizedEvent
	//adds value to Timestamp, Host, Program,Message and RawLine
	for scanner.Scan() {
		line, err := ParseLine(scanner.Text())

		if err != nil {
			continue
		}
		logs = append(logs, line)

	}

	return logs, err

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
		LogSource: "auth.log",
		Program:   matches[3],
		Message:   matches[4],
		RawLine:   line,
	}

	switch event.Program {
	case "sshd":
		event = SSHParser(event)
		if event == nil {
		}
	case "sudo":
	case "su":
	case "passwd":
	case "useradd":
	case "userdel":
	case "usermod":
	case "polkitd":
	}

	return event, err
}
