package detection

import "github.com/Kes0x6f/Log-Based--IDS/internal/model"

type RuleRegistry struct {
	byProgramEvent map[string]map[string][]Rule
}

func NewRuleRegistry(rules []Rule) *RuleRegistry {
	reg := &RuleRegistry{
		byProgramEvent: make(map[string]map[string][]Rule),
	}

	for _, rule := range rules {
		meta := rule.Meta()

		// ensure program exists
		if reg.byProgramEvent[meta.Program] == nil {
			reg.byProgramEvent[meta.Program] = make(map[string][]Rule)
		}

		// index by event types
		for _, evt := range meta.EventTypes {
			reg.byProgramEvent[meta.Program][evt] =
				append(reg.byProgramEvent[meta.Program][evt], rule)
		}
	}

	return reg
}

func (r *RuleRegistry) GetRules(event *model.NormalizedEvent) []Rule {
	if progMap, ok := r.byProgramEvent[event.Program]; ok {
		if rules, ok := progMap[event.EventType]; ok {
			return rules
		}
	}
	return nil
}
