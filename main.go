package main

import (
	"context"
	"log"
	"os"
	"os/signal"
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
	db, err := database.InitDB("data/ids.db")
	if err != nil {
		log.Fatal(err)
	}
	err = database.CreateTables(db)
	if err != nil {
		log.Fatal(err)
	}
	alertRepo := &database.AlertRepository{DB: db}
	settingsRepo := &database.SettingsRepository{DB: db}
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
	go server.Start(":8888")

	rawLogChan := make(chan collector.RawLog, 1000)
	parseChan := make(chan *model.NormalizedEvent, 1000)
	alertChan := make(chan *model.Alert, 1000)

	filecollectors := []collector.FileCollector{
		{
			FilePath:    "/var/log/auth.log",
			Source:      "auth",
			Broadcaster: broadcaster,
			Stats:       stats,
		},
		{
			FilePath:    "/var/log/kern.log",
			Source:      "kern",
			Broadcaster: broadcaster,
			Stats:       stats,
		},
		{
			// Raw auditd log — ParserWorker detects "type=..." lines and
			// bypasses the syslog header regex automatically.
			FilePath:    "/var/log/audit/audit.log",
			Source:      "audit",
			Broadcaster: broadcaster,
			Stats:       stats,
		},
		{
			FilePath:    "/var/log/apache2/access.log",
			Source:      "apache2",
			Broadcaster: broadcaster,
			Stats:       stats,
		},
		{
			FilePath:    "/var/log/nginx/access.log",
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
		authrule.NewSudoBruteForceRule(),
		authrule.NewSudoSuccessAfterFailRule(),
		authrule.NewSudoSensitiveCommandRule(),
		authrule.NewSudoCommandAbuseRule(),
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

		// ── Web (Apache2 / Nginx) ─────────────────────────────────────────────
		webrule.NewWebScannerUARule(),
		webrule.NewWebPathProbeRule(),
		webrule.NewWeb404Rule(),
		webrule.NewWebAuthBruteRule(),
		webrule.NewWebMethodRule(),
		webrule.NewWebFloodRule(),
	})

	for _, c := range filecollectors {
		go c.Start(rawLogChan)
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
