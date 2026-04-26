package main

import (
	"log"

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
		{
			FilePath:    "/var/log/auth.log",
			Source:      "auth",
			Broadcaster: broadcaster,
		},
		{
			FilePath:    "/var/log/ufw.log",
			Source:      "ufw",
			Broadcaster: broadcaster,
		},
		{
			FilePath:    "/var/log/kern.log",
			Source:      "kern",
			Broadcaster: broadcaster,
		},
		//{
		//	// Raw auditd log — ParserWorker detects "type=..." lines from this
		//	// source and bypasses the syslog header regex automatically.
		//	FilePath:    "/var/log/audit/audit.log",
		//	Source:      "audit",
		//	Broadcaster: broadcaster,
		//},
		{
			// Apache2 access log — Combined Log Format, no syslog header.
			// Comment out if Apache is not installed.
			FilePath:    "/var/log/apache2/access.log",
			Source:      "apache2",
			Broadcaster: broadcaster,
		},
		{
			// Nginx access log — same Combined Log Format as Apache.
			// Comment out if Nginx is not installed.
			FilePath:    "/var/log/nginx/access.log",
			Source:      "nginx",
			Broadcaster: broadcaster,
		},
	}

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
		authrule.NewGroupModifiedRule(), // was duplicated in previous main.go — fixed
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

	for _, c := range filecollector {
		go c.Start(rawLogChan)
	}

	go parser.ParserWorker(rawLogChan, parseChan)
	go engine.Process(parseChan, alertChan)
	go alertManager.Start(alertChan)
	select {}
}
