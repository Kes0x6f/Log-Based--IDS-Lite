package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/Kes0x6f/Log-Based--IDS/internal/alert"
	"github.com/Kes0x6f/Log-Based--IDS/internal/api"
	"github.com/Kes0x6f/Log-Based--IDS/internal/collector"
	"github.com/Kes0x6f/Log-Based--IDS/internal/database"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	auditrule "github.com/Kes0x6f/Log-Based--IDS/internal/detection/rules/audit"
	authrule "github.com/Kes0x6f/Log-Based--IDS/internal/detection/rules/auth"
	kernrule "github.com/Kes0x6f/Log-Based--IDS/internal/detection/rules/kernel"
	webrule "github.com/Kes0x6f/Log-Based--IDS/internal/detection/rules/web"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
	"github.com/Kes0x6f/Log-Based--IDS/internal/parser"
	"github.com/Kes0x6f/Log-Based--IDS/internal/stream"
)

func main() {
	log.Println("MAIN STARTED")

	// ── Config from environment (falls back to safe defaults) ───────────────
	// Override any value without recompiling:
	//   IDS_ADDR=0.0.0.0:8888 IDS_DB=data/ids.db sudo ./ids-agent
	env := func(key, def string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		return def
	}

	listenAddr := env("IDS_ADDR", "127.0.0.1:8888")
	dbPath := env("IDS_DB", "data/ids.db")
	logAuth := env("IDS_LOG_AUTH", "/var/log/auth.log")
	logKern := env("IDS_LOG_KERN", "/var/log/kern.log")
	logAudit := env("IDS_LOG_AUDIT", "/var/log/audit/audit.log")
	logApache := env("IDS_LOG_APACHE", "/var/log/apache2/access.log")
	logNginx := env("IDS_LOG_NGINX", "/var/log/nginx/access.log")

	// ── Context & signal handling ────────────────────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("received signal %v — shutting down", sig)
		cancel()
	}()

	// ── Database ─────────────────────────────────────────────────────────────
	// Ensure the directory that holds the database file exists.
	// Works for both the default relative path ("data/ids.db") and any
	// absolute path set via IDS_DB (e.g. "/var/lib/ids/ids.db").
	if dbDir := filepath.Dir(dbPath); dbDir != "" && dbDir != "." {
		if err := os.MkdirAll(dbDir, 0750); err != nil {
			log.Fatal("cannot create database directory:", err)
		}
	}
	db, err := database.InitDB(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	err = database.CreateTables(db)
	if err != nil {
		log.Fatal(err)
	}
	alertRepo := &database.AlertRepository{DB: db}
	settingsRepo := &database.SettingsRepository{DB: db}
	ruleConfigRepo := &database.RuleConfigRepository{DB: db}
	alertManager := &alert.Manager{
		AlertRepo:    alertRepo,
		SettingsRepo: settingsRepo,
	}

	// ── Infrastructure ────────────────────────────────────────────────────────
	broadcaster := stream.NewBroadcaster()

	// Shared per-source line counters exposed via /sources/status
	stats := collector.NewSourceStats()

	apiHandler := &api.Handler{
		Repo:         alertRepo,
		SettingsRepo: settingsRepo,
		Broadcaster:  broadcaster,
		Stats:        stats,
	}
	router := api.NewRouter(apiHandler)
	server := &api.Server{Handler: router}
	go server.Start(listenAddr)

	rawLogChan := make(chan collector.RawLog, 1000)
	parseChan := make(chan *model.NormalizedEvent, 1000)
	alertChan := make(chan *model.Alert, 1000)

	filecollectors := []collector.FileCollector{
		{
			FilePath:    logAuth,
			Source:      "auth",
			Broadcaster: broadcaster,
			Stats:       stats,
		},
		{
			FilePath:    logKern,
			Source:      "kern",
			Broadcaster: broadcaster,
			Stats:       stats,
		},
		{
			// Raw auditd log — ParserWorker detects "type=..." lines and
			// bypasses the syslog header regex automatically.
			FilePath:    logAudit,
			Source:      "audit",
			Broadcaster: broadcaster,
			Stats:       stats,
		},
		{
			FilePath:    logApache,
			Source:      "apache2",
			Broadcaster: broadcaster,
			Stats:       stats,
		},
		{
			FilePath:    logNginx,
			Source:      "nginx",
			Broadcaster: broadcaster,
			Stats:       stats,
		},
	}

	// ── Detection engine ──────────────────────────────────────────────────────
	engine := detection.NewEngine([]detection.Rule{
		// ── SSH ──────────────────────────────────────────────────────────────
		authrule.NewSSHBruteForceRule(),
		authrule.NewSSHEnumerationRule(),
		authrule.NewSSHSuccessAfterFailRule(),
		authrule.NewSSHInvalidUserRule(),
		authrule.NewSSHReconnectRule(),
		authrule.NewSSHRootTargetRule(),
		authrule.NewSSHDistributedBruteForceRule(),

		// ── SUDO ─────────────────────────────────────────────────────────────
		// SudoCommandAbuseRule must be before SudoSensitiveCommandRule:
		// it writes command-frequency data into the shared sudo context that
		// SudoSensitiveCommandRule reads for risk scoring.
		authrule.NewSudoBruteForceRule(),
		authrule.NewSudoSuccessAfterFailRule(),
		authrule.NewSudoCommandAbuseRule(),
		authrule.NewSudoSensitiveCommandRule(),
		authrule.NewSudoRootAbuseRule(),
		authrule.NewSudoSessionAbuseRule(),

		// ── SU ───────────────────────────────────────────────────────────────
		authrule.NewSuBruteForceRule(),
		authrule.NewSuSuccessAfterFailRule(),

		// ── Account / credential ─────────────────────────────────────────────
		authrule.NewAccountCreatedRule(),
		authrule.NewGroupModifiedRule(),
		authrule.NewPasswdChangedRule(),

		// ── UFW / Firewall ───────────────────────────────────────────────────
		kernrule.NewUFWPortScanRule(),
		kernrule.NewUFWRepeatedBlockRule(),
		kernrule.NewUFWBlockStormRule(),
		kernrule.NewUFWSensitivePortRule(),
		kernrule.NewUFWOutboundBlockRule(),

		// ── Kernel ───────────────────────────────────────────────────────────
		kernrule.NewKernModuleLoadRule(),
		kernrule.NewKernSegfaultRule(),
		kernrule.NewKernOOMKillRule(),
		kernrule.NewKernDiskErrorRule(),

		// ── Auditd ───────────────────────────────────────────────────────────
		auditrule.NewAuditFileReadRule(),
		auditrule.NewAuditFileWriteRule(),
		auditrule.NewAuditCronWriteRule(),
		auditrule.NewAuditServiceWriteRule(),
		auditrule.NewAuditSetuidRule(),
		auditrule.NewAuditPtraceRule(),
		auditrule.NewAuditCapsetRule(),
		auditrule.NewAuditExecTmpRule(),
		auditrule.NewUFWRuleChangeRule(),

		// ── Web (Apache2 / Nginx) ─────────────────────────────────────────────
		webrule.NewWebScannerUARule(),
		webrule.NewWebPathProbeRule(),
		webrule.NewWeb404Rule(),
		webrule.NewWebAuthBruteRule(),
		webrule.NewWebMethodRule(),
		webrule.NewWebFloodRule(),
	}, ruleConfigRepo, settingsRepo)

	apiHandler.RuleConfigRepo = ruleConfigRepo
	apiHandler.Engine = engine

	for _, c := range filecollectors {
		c := c // capture loop variable
		go func() {
			if err := c.Start(rawLogChan); err != nil {
				// Optional sources (apache2, nginx, audit) may not exist on every
				// host — log as a warning so the operator knows, but keep running.
				log.Printf("collector [%s] failed to start (%s): %v", c.Source, c.FilePath, err)
			}
		}()
	}

	// ── NFLOG collector ───────────────────────────────────────────────────────
	// We use a WaitGroup so main() blocks until NFLOGCollector.Start returns
	// and its deferred teardown() removes the iptables rules.
	// Without this, main() exits the moment ctx is cancelled and the process
	// is killed before defer teardown() can run — leaving stale iptables rules.
	nflogCollector := &collector.NFLOGCollector{
		Broadcaster: broadcaster,
		Stats:       stats,
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		nflogCollector.Start(ctx, parseChan)
	}()

	go parser.ParserWorker(rawLogChan, parseChan)
	go engine.Process(parseChan, alertChan)
	go alertManager.Start(alertChan)

	// Block until signal received.
	<-ctx.Done()

	// Wait for NFLOGCollector to finish its deferred teardown before we exit.
	// This guarantees iptables rules are always cleaned up.
	log.Println("waiting for NFLOGCollector teardown...")
	wg.Wait()
	log.Println("shutdown complete")
}
