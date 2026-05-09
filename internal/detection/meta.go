package detection

// RuleMeta describes a rule to the registry and the engine.
// The three fields (DisplayName, Description, Defaults) are optional
type RuleMeta struct {
	LogSource  string
	Program    string
	EventTypes []string

	// DisplayName is the human-readable rule name used as the primary key
	// in the rule_config table. It must match the first argument passed to
	// model.NewAlert() inside the rule's Evaluate() method so that alert
	// records and config rows refer to the same rule by the same name.
	DisplayName string
	// Description is shown on the Rules Manager card in the UI.
	Description string

	// Defaults are the compile-time limits for this rule.
	// The engine's Resolve() method uses these when no DB override exists.
	Defaults RuleDefaults
}
