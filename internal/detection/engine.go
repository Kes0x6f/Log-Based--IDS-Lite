package detection

import (
	"fmt"

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

func (e *Engine) Process(input <-chan *model.NormalizedEvent, output chan<- *model.Alert) {
	for event := range input {
		fmt.Println("printing event")
		for _, rule := range e.Rules {

			for _, alert := range rule.Evaluate(event, e.State) {
				fmt.Println("printing an lert", alert)
				output <- alert
			}
		}
	}
}
