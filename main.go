package main

import (
	"log"

	"github.com/Kes0x6f/Log-Based--IDS/internal/alert"
	"github.com/Kes0x6f/Log-Based--IDS/internal/api"
	"github.com/Kes0x6f/Log-Based--IDS/internal/collector"
	"github.com/Kes0x6f/Log-Based--IDS/internal/database"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	rule "github.com/Kes0x6f/Log-Based--IDS/internal/detection/rules/auth"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
	"github.com/Kes0x6f/Log-Based--IDS/internal/parser"
	"github.com/Kes0x6f/Log-Based--IDS/internal/stream"
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

	broadcaster := stream.NewBroadcaster()

	apiHandler := &api.Handler{
		Repo:        alertRepo,
		Broadcaster: broadcaster,
	}

	router := api.NewRouter(apiHandler)

	server := &api.Server{
		Handler: router,
	}

	go server.Start(":8888")

	rawLogChan := make(chan collector.RawLog, 1000)
	parseChan := make(chan *model.NormalizedEvent, 1000)
	alertChan := make(chan *model.Alert, 1000)

	filecollector := []collector.FileCollector{
		{FilePath: "/var/log/auth.log",
			Source:      "auth",
			Broadcaster: broadcaster},
	}
	engine := detection.NewEngine([]detection.Rule{
		rule.NewSSHBruteForceRule(),
		rule.NewSSHEnumerationRule(),
		rule.NewSSHSuccessAfterFailRule(),
		rule.NewSSHInvalidUserRule(),
		rule.NewSSHReconnectRule(),
		rule.NewSSHRootTargetRule(),
		rule.NewSSHDistributedBruteForceRule(),

		rule.NewSudoBruteForceRule(),
		rule.NewSudoSuccessAfterFailRule(),
		rule.NewSudoSensitiveCommandRule(),
		rule.NewSudoCommandAbuseRule(),
		rule.NewSudoRootAbuseRule(),
	})

	for _, c := range filecollector {
		go c.Start(rawLogChan)
	}

	go parser.ParserWorker(rawLogChan, parseChan)
	go engine.Process(parseChan, alertChan)
	go alertManager.Start(alertChan)
	select {}
}
