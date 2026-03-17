package main

import (
	///"github.com/Kes0x6f/Log-Based--IDS/internal/collector"
	///"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	///rule "github.com/Kes0x6f/Log-Based--IDS/internal/detection/rules"
	"log"

	"github.com/Kes0x6f/Log-Based--IDS/internal/alert"
	"github.com/Kes0x6f/Log-Based--IDS/internal/collector"
	"github.com/Kes0x6f/Log-Based--IDS/internal/database"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	rule "github.com/Kes0x6f/Log-Based--IDS/internal/detection/rules"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
	"github.com/Kes0x6f/Log-Based--IDS/internal/parser"
)

func main() {

	log.Println("MAIN STARTED")
	db, err := database.InitDB("data/ids.db")
	if err != nil {
		log.Fatal(err)
	}
	err = database.CreateTables(db)
	if err != nil {
		log.Fatal(err)
	}
	alertRepo := &database.AlertRepository{DB: db}
	alertManager := &alert.Manager{
		AlertRepo: alertRepo,
	}

	rawLogChan := make(chan collector.RawLog, 100)
	parseChan := make(chan *model.NormalizedEvent, 1000)
	alertChan := make(chan *model.Alert, 100)

	filecollector := collector.FileCollector{
		FilePath: "logs/sample_auth.log",
	}
	engine := detection.NewEngine([]detection.Rule{
		rule.NewSSHRule(),
	})

	go filecollector.Start(rawLogChan)
	go parser.ParserWorker(rawLogChan, parseChan)
	go engine.Process(parseChan, alertChan)
	go alertManager.Start(alertChan)
	select {}
}
