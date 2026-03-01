package detection

import (
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

type Rule interface {
	Evaluate(event *model.NormalizedEvent, state *context.DetectionContext) []string
}
