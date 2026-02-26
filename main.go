package main

import (
	"fmt"

	authEngine "github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/parser"
)

func main() {

	p := parser.GetParser("auth")
	events, _ := p.Parse("logs/sample_auth.log")

	for _, e := range events {
		fmt.Println(*e)
	}

	detectedAlerts := authEngine.AuthEngine(events)

	for _, alert := range detectedAlerts {
		fmt.Println(alert)
	}
}
