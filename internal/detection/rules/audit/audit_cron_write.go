package rule

import (
	"fmt"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// AuditCronWriteRule fires whenever a file is written inside a cron directory
// or the system crontab. Creating or modifying cron jobs is one of the most
// common persistence techniques used after initial access.
//
// No cooldown — every cron write is independently notable.
//
// Required auditd rules:
//
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F dir=/etc/cron.d        -F perm=w -k cron_write
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F dir=/etc/cron.daily    -F perm=w -k cron_write
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F dir=/etc/cron.hourly   -F perm=w -k cron_write
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F dir=/etc/cron.weekly   -F perm=w -k cron_write
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F dir=/etc/cron.monthly  -F perm=w -k cron_write
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F dir=/var/spool/cron    -F perm=w -k cron_write
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F path=/etc/crontab      -F perm=w -k cron_write
type AuditCronWriteRule struct{}

func NewAuditCronWriteRule() *AuditCronWriteRule {
	return &AuditCronWriteRule{}
}

func (r *AuditCronWriteRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:   "audit",
		Program:     "auditd",
		EventTypes:  []string{"CRON_WRITE"},
		DisplayName: "Cron Job Created or Modified",
		Description: "File written to any cron directory or /etc/crontab — classic persistence mechanism.",
		Defaults:    detection.RuleDefaults{},
	}
}

func (r *AuditCronWriteRule) Evaluate(event *model.NormalizedEvent, _ *context.DetectionContext, cfg detection.ResolvedConfig) []*model.Alert {
	filePath := event.Command
	user := event.Username

	if filePath == "" {
		return nil
	}

	exeLabel := event.CallerExe
	if exeLabel == "" {
		exeLabel = "unknown"
	}

	return []*model.Alert{
		model.NewAlert(
			"Cron Job Created or Modified",
			model.SeverityHigh,
			"persistence",
			fmt.Sprintf("%s wrote cron file %s (user: %s)", exeLabel, filePath, user),
			event,
			1,
		),
	}
}
