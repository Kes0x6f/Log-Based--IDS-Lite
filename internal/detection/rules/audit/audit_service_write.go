package rule

import (
	"fmt"
	"strings"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// Suppress alerts on directory paths — auditd emits these when the
// directory itself is opened, not when a unit file inside it is written.
// A real unit file always has a recognised systemd extension.
var systemdUnitExtensions = []string{
	".service", ".socket", ".timer", ".target",
	".mount", ".automount", ".path", ".slice", ".scope",
}

func isSystemdUnitFile(path string) bool {
	for _, ext := range systemdUnitExtensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// serviceWriteDpkgSuffixes are staging-file endings that dpkg/apt create when
// installing or upgrading systemd unit files.  These are not real persistence
// installs — dpkg atomically renames them into place after the write.
var serviceWriteDpkgSuffixes = []string{
	".dpkg-tmp", ".dpkg-new", ".dpkg-old", ".dpkg-bak", ".dpkg-dist",
}

// serviceWriteTrustedExes are package-manager processes that legitimately write
// unit files during controlled package installation.
var serviceWriteTrustedExes = map[string]bool{
	"/usr/bin/dpkg":    true,
	"/usr/bin/apt":     true,
	"/usr/bin/apt-get": true,
}

func isServiceWriteFalsePositive(filePath, exe string) bool {
	for _, sfx := range serviceWriteDpkgSuffixes {
		if strings.HasSuffix(filePath, sfx) {
			return true
		}
	}
	return serviceWriteTrustedExes[exe]
}

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
		LogSource:   "audit",
		Program:     "auditd",
		EventTypes:  []string{"SERVICE_WRITE"},
		DisplayName: "Systemd Service Created or Modified",
		Description: "Systemd unit file written to system directories — boot-persistent execution backdoor.",
		Defaults:    detection.RuleDefaults{},
	}
}

func (r *AuditServiceWriteRule) Evaluate(event *model.NormalizedEvent, _ *context.DetectionContext, cfg detection.ResolvedConfig) []*model.Alert {
	filePath := event.Command
	user := event.Username

	if filePath == "" {
		return nil
	}

	if !isSystemdUnitFile(filePath) {
		return nil
	}

	if isServiceWriteFalsePositive(filePath, event.CallerExe) {
		return nil
	}

	exeLabel := event.CallerExe
	if exeLabel == "" {
		exeLabel = "unknown"
	}

	return []*model.Alert{
		model.NewAlert(
			"Systemd Service Created or Modified",
			model.SeverityCritical,
			"persistence",
			fmt.Sprintf("%s wrote systemd unit %s (user: %s)", exeLabel, filePath, user),
			event,
			1,
		),
	}
}
