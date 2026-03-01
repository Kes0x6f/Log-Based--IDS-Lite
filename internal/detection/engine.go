package detection

import (
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

type Engine struct {
	Rules []Rule
	State *context.DetectionContext
}

func NewEngine(rules []Rule) *Engine {
	return &Engine{
		Rules: rules,
		State: context.NewDetectionContext(),
	}

}
func (e *Engine) Process(events []*model.NormalizedEvent) []string {
	var alerts []string
	for _, event := range events {
		for _, rule := range e.Rules {
			if alert := rule.Evaluate(event, e.State); alert != nil {
				alerts = append(alerts, alert...)
			}
		}
	}

	return alerts
}
