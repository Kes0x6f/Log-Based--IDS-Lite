package main

import (
	"fmt"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	rule "github.com/Kes0x6f/Log-Based--IDS/internal/detection/rules"
	"github.com/Kes0x6f/Log-Based--IDS/internal/parser"
)

func main() {

	p := parser.GetParser("auth")
	events, _ := p.Parse("logs/sample_auth.log")

	engine := detection.NewEngine([]detection.Rule{
		rule.NewSSHRule(),
	})

	detectedAlerts := engine.Process(events)

	for _, alert := range detectedAlerts {
		fmt.Println(alert)
	}
}
