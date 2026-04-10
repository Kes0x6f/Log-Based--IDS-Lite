package detection

import (
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

type Engine struct {
	Registry *RuleRegistry
	State    *context.DetectionContext
}

func NewEngine(rules []Rule) *Engine {
	return &Engine{
		Registry: NewRuleRegistry(rules),
		State:    context.NewDetectionContext(),
	}
}

func (e *Engine) Process(input <-chan *model.NormalizedEvent, output chan<- *model.Alert) {
	for event := range input {

		rules := e.Registry.GetRules(event)

		for _, rule := range rules {
			for _, alert := range rule.Evaluate(event, e.State) {
				output <- alert
			}
		}
	}
}
