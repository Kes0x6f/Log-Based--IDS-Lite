package main

import (
	///"github.com/Kes0x6f/Log-Based--IDS/internal/collector"
	///"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	///rule "github.com/Kes0x6f/Log-Based--IDS/internal/detection/rules"
	"github.com/Kes0x6f/Log-Based--IDS/internal/collector"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	rule "github.com/Kes0x6f/Log-Based--IDS/internal/detection/rules"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
	"github.com/Kes0x6f/Log-Based--IDS/internal/parser"
)

func main() {

	///p := parser.GetParser("auth")
	///events, _ := p.Parse("logs/sample_auth.log")

	///engine := detection.NewEngine([]detection.Rule{
	///	rule.NewSSHRule(),
	///})

	/// := engine.Process(events)
	///
	///for _, alert := range detectedAlerts {
	///	fmt.Println(alert)
	///}

	//adding channels

	rawLogChan := make(chan collector.RawLog)
	parseChan := make(chan *model.NormalizedEvent, 1000)
	//eventChan := make(chan *model.NormalizedEvent, 100)
	alertChan := make(chan *model.Alert, 100)

	collector := collector.FileCollector{
		FilePath: "logs/sample_auth.log",
	}
	engine := detection.NewEngine([]detection.Rule{
		rule.NewSSHRule(),
	})
	go collector.Start(rawLogChan)

	go parser.ParserWorker(rawLogChan, parseChan)

	go engine.Process(parseChan, alertChan)

	select {}
}
