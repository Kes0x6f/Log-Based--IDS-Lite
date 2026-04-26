package rule

import (
	"fmt"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// AuditServiceWriteRule fires whenever a file is written to a systemd unit
// directory. Installing a new service is a reliable, boot-persistent
// execution mechanism and a top-tier persistence technique.
//
// No cooldown — every service write is independently notable.
//
// Required auditd rules:
//
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F dir=/etc/systemd/system   -F perm=w -k service_write
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F dir=/lib/systemd/system   -F perm=w -k service_write
//	-a always,exit -F arch=b64 -S open,openat,openat2 -F dir=/usr/lib/systemd/system -F perm=w -k service_write
type AuditServiceWriteRule struct{}

func NewAuditServiceWriteRule() *AuditServiceWriteRule {
	return &AuditServiceWriteRule{}
}

func (r *AuditServiceWriteRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:  "audit",
		Program:    "auditd",
		EventTypes: []string{"SERVICE_WRITE"},
	}
}

func (r *AuditServiceWriteRule) Evaluate(event *model.NormalizedEvent, _ *context.DetectionContext) []*model.Alert {
	filePath := event.Command
	user := event.Username

	if filePath == "" {
		return nil
	}

	return []*model.Alert{
		model.NewAlert(
			"Systemd Service Created or Modified",
			model.SeverityCritical,
			"persistence",
			fmt.Sprintf("Systemd unit file written: %s (user: %s) — possible persistence mechanism", filePath, user),
			event,
			1,
		),
	}
}
