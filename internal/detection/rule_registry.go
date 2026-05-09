package detection

import "github.com/Kes0x6f/Log-Based--IDS/internal/model"

type RuleRegistry struct {
	index map[string]map[string]map[string][]Rule
	//     logSource  → program   → eventType → rules
}

func NewRuleRegistry(rules []Rule) *RuleRegistry {
	reg := &RuleRegistry{
		index: make(map[string]map[string]map[string][]Rule),
	}
	for _, rule := range rules {
		meta := rule.Meta()
		if reg.index[meta.LogSource] == nil {
			reg.index[meta.LogSource] = make(map[string]map[string][]Rule)
		}
		if reg.index[meta.LogSource][meta.Program] == nil {
			reg.index[meta.LogSource][meta.Program] = make(map[string][]Rule)
		}
		for _, evt := range meta.EventTypes {
			reg.index[meta.LogSource][meta.Program][evt] =
				append(reg.index[meta.LogSource][meta.Program][evt], rule)
		}
	}
	return reg
}

func (r *RuleRegistry) GetRules(event *model.NormalizedEvent) []Rule {
	if src, ok := r.index[event.LogSource]; ok {
		if prog, ok := src[event.Program]; ok {
			return prog[event.EventType]
		}
	}
	return nil
}

func (r *RuleRegistry) AllRules() []Rule {
	seen := make(map[Rule]struct{})
	var out []Rule
	for _, programs := range r.index {
		for _, eventTypes := range programs {
			for _, rules := range eventTypes {
				for _, rule := range rules {
					if _, ok := seen[rule]; !ok {
						seen[rule] = struct{}{}
						out = append(out, rule)
					}
				}
			}
		}
	}
	return out
}
