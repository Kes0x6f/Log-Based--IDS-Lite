package rule

import (
	"fmt"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// KernModuleLoadRule fires on every out-of-tree or unsigned kernel module load.
//
// Why it matters:
//   - Legitimate kernel modules ship with the kernel or a known DKMS package
//     and are signed. Out-of-tree + unsigned is the standard rootkit delivery
//     mechanism (e.g. Reptile, Diamorphine, Necro).
//   - A single unexplained KMOD_LOAD is enough to warrant investigation.
//     There is intentionally no cooldown — if an attacker loads 3 modules
//     in a row, we want 3 alerts.
type KernModuleLoadRule struct{}

func NewKernModuleLoadRule() *KernModuleLoadRule {
	return &KernModuleLoadRule{}
}

func (r *KernModuleLoadRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:  "kern",
		Program:    "kernel",
		EventTypes: []string{"KMOD_LOAD"},
	}
}

func (r *KernModuleLoadRule) Evaluate(event *model.NormalizedEvent, _ *context.DetectionContext) []*model.Alert {
	moduleName := event.Command
	if moduleName == "" {
		moduleName = "unknown"
	}

	msg := fmt.Sprintf(
		"Unsigned/out-of-tree kernel module loaded: %s — possible rootkit", moduleName,
	)

	return []*model.Alert{
		model.NewAlert(
			"Kernel Module Load",
			model.SeverityCritical,
			"rootkit",
			msg,
			event,
			1,
		),
	}
}
