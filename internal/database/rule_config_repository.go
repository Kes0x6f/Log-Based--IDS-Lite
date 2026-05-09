package database

import (
	"database/sql"
	"strconv"
	"time"
)

// RuleConfig is one row in rule_config.
// Threshold, WindowSec, and CooldownSec are pointers so nil means
// "no override — use the compiled default."
type RuleConfig struct {
	RuleName    string    `json:"rule_name"`
	Threshold   *int      `json:"threshold"`
	WindowSec   *int      `json:"window_sec"`
	CooldownSec *int      `json:"cooldown_sec"`
	Enabled     bool      `json:"enabled"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RuleConfigHistory is one row in rule_config_history.
type RuleConfigHistory struct {
	ID        int64     `json:"id"`
	RuleName  string    `json:"rule_name"`
	Field     string    `json:"field"`
	OldValue  *string   `json:"old_value"` // nil = was at compiled default
	NewValue  *string   `json:"new_value"` // nil = reset to compiled default
	ChangedAt time.Time `json:"changed_at"`
	ChangedBy string    `json:"changed_by"`
}

type RuleConfigRepository struct {
	DB *sql.DB
}

// ── Read ──────────────────────────────────────────────────────────────────────

// GetAll returns every row as a map keyed by rule_name.
// The engine calls this on cache refresh.
func (r *RuleConfigRepository) GetAll() (map[string]RuleConfig, error) {
	rows, err := r.DB.Query(`
		SELECT rule_name, threshold, window_sec, cooldown_sec, enabled, updated_at
		FROM   rule_config
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]RuleConfig)
	for rows.Next() {
		var cfg RuleConfig
		var threshold, windowSec, cooldownSec sql.NullInt64

		if err := rows.Scan(
			&cfg.RuleName, &threshold, &windowSec, &cooldownSec,
			&cfg.Enabled, &cfg.UpdatedAt,
		); err != nil {
			return nil, err
		}

		if threshold.Valid {
			v := int(threshold.Int64)
			cfg.Threshold = &v
		}
		if windowSec.Valid {
			v := int(windowSec.Int64)
			cfg.WindowSec = &v
		}
		if cooldownSec.Valid {
			v := int(cooldownSec.Int64)
			cfg.CooldownSec = &v
		}

		out[cfg.RuleName] = cfg
	}
	return out, rows.Err()
}

// Get returns one rule's config, or (RuleConfig{Enabled:true}, false, nil)
// when no override row exists.
func (r *RuleConfigRepository) Get(ruleName string) (RuleConfig, bool, error) {
	var cfg RuleConfig
	cfg.RuleName = ruleName
	cfg.Enabled = true

	var threshold, windowSec, cooldownSec sql.NullInt64
	err := r.DB.QueryRow(`
    SELECT threshold, window_sec, cooldown_sec, enabled, updated_at
    FROM rule_config WHERE rule_name = ?
`, ruleName).Scan(&threshold, &windowSec, &cooldownSec, &cfg.Enabled, &cfg.UpdatedAt)

	if err == sql.ErrNoRows {
		return cfg, false, nil
	}
	if err != nil {
		return cfg, false, err
	}

	if threshold.Valid {
		v := int(threshold.Int64)
		cfg.Threshold = &v
	}
	if windowSec.Valid {
		v := int(windowSec.Int64)
		cfg.WindowSec = &v
	}
	if cooldownSec.Valid {
		v := int(cooldownSec.Int64)
		cfg.CooldownSec = &v
	}

	return cfg, true, nil
}

// GetHistory returns up to `limit` history rows for one rule, newest first.
// Called by GET /rule-configs/history.
func (r *RuleConfigRepository) GetHistory(ruleName string, limit int) ([]RuleConfigHistory, error) {
	if limit <= 0 {
		limit = 20
	}

	rows, err := r.DB.Query(`
		SELECT id, rule_name, field, old_value, new_value, changed_at, changed_by
		FROM   rule_config_history
		WHERE  rule_name = ?
		ORDER  BY changed_at DESC, id DESC
		LIMIT  ?
	`, ruleName, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RuleConfigHistory
	for rows.Next() {
		var h RuleConfigHistory
		var oldVal, newVal sql.NullString

		if err := rows.Scan(
			&h.ID, &h.RuleName, &h.Field,
			&oldVal, &newVal,
			&h.ChangedAt, &h.ChangedBy,
		); err != nil {
			return nil, err
		}
		if oldVal.Valid {
			h.OldValue = &oldVal.String
		}
		if newVal.Valid {
			h.NewValue = &newVal.String
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ── Write ─────────────────────────────────────────────────────────────────────

// Upsert inserts or replaces a rule's config row, then records one history
// entry for each field whose value changed.
func (r *RuleConfigRepository) Upsert(cfg RuleConfig) error {
	// Read current state before overwriting so we can diff for history.
	old, oldExists, err := r.Get(cfg.RuleName)
	if err != nil {
		return err
	}

	_, err = r.DB.Exec(`
		INSERT INTO rule_config (rule_name, threshold, window_sec, cooldown_sec, enabled, updated_at)
		VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(rule_name) DO UPDATE SET
			threshold    = excluded.threshold,
			window_sec   = excluded.window_sec,
			cooldown_sec = excluded.cooldown_sec,
			enabled      = excluded.enabled,
			updated_at   = CURRENT_TIMESTAMP
	`, cfg.RuleName, cfg.Threshold, cfg.WindowSec, cfg.CooldownSec, cfg.Enabled)
	if err != nil {
		return err
	}

	return r.writeHistory(cfg.RuleName, old, oldExists, cfg)
}

// SetEnabled toggles a rule on or off without changing threshold/window/cooldown.
func (r *RuleConfigRepository) SetEnabled(ruleName string, enabled bool) error {
	_, err := r.DB.Exec(`
		INSERT INTO rule_config (rule_name, enabled, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(rule_name) DO UPDATE SET
			enabled    = excluded.enabled,
			updated_at = CURRENT_TIMESTAMP
	`, ruleName, enabled)
	return err
}

// Reset deletes one rule's override row and records what was removed in history.
func (r *RuleConfigRepository) Reset(ruleName string) error {
	old, exists, err := r.Get(ruleName)
	if err != nil {
		return err
	}

	if _, err = r.DB.Exec(`DELETE FROM rule_config WHERE rule_name = ?`, ruleName); err != nil {
		return err
	}

	if !exists {
		return nil
	}

	// Log each field that had an override, showing it returning to compiled default.
	return r.writeHistory(ruleName, old, true, RuleConfig{
		RuleName: ruleName,
		Enabled:  true, // the no-override default
	})
}

// ResetAll removes every override row and logs the event for each affected rule.
func (r *RuleConfigRepository) ResetAll() error {
	// Write history before deleting so we still have the rule names.
	if _, err := r.DB.Exec(`
		INSERT INTO rule_config_history (rule_name, field, old_value, new_value)
		SELECT rule_name, 'reset-all', 'override', NULL FROM rule_config
	`); err != nil {
		return err
	}
	_, err := r.DB.Exec(`DELETE FROM rule_config`)
	return err
}

// ── Private helpers ───────────────────────────────────────────────────────────

// writeHistory diffs old and new RuleConfigs and inserts one history row per
// changed field. Fields with identical values before and after are skipped.
func (r *RuleConfigRepository) writeHistory(
	ruleName string,
	old RuleConfig,
	oldExists bool,
	new RuleConfig,
) error {
	intStr := func(v *int) *string {
		if v == nil {
			return nil
		}
		s := strconv.Itoa(*v)
		return &s
	}
	boolStr := func(v bool) *string {
		s := strconv.FormatBool(v)
		return &s
	}

	type fieldDiff struct {
		name     string
		oldValue *string
		newValue *string
	}

	var diffs []fieldDiff

	// Threshold
	var oldTh *string
	if oldExists {
		oldTh = intStr(old.Threshold)
	}
	newTh := intStr(new.Threshold)
	if !ptrStrEq(oldTh, newTh) {
		diffs = append(diffs, fieldDiff{"threshold", oldTh, newTh})
	}

	// Window
	var oldWs *string
	if oldExists {
		oldWs = intStr(old.WindowSec)
	}
	newWs := intStr(new.WindowSec)
	if !ptrStrEq(oldWs, newWs) {
		diffs = append(diffs, fieldDiff{"window_sec", oldWs, newWs})
	}

	// Cooldown
	var oldCs *string
	if oldExists {
		oldCs = intStr(old.CooldownSec)
	}
	newCs := intStr(new.CooldownSec)
	if !ptrStrEq(oldCs, newCs) {
		diffs = append(diffs, fieldDiff{"cooldown_sec", oldCs, newCs})
	}

	// Enabled — only log when it actually changes value
	if oldExists {
		oldEn := boolStr(old.Enabled)
		newEn := boolStr(new.Enabled)
		if !ptrStrEq(oldEn, newEn) {
			diffs = append(diffs, fieldDiff{"enabled", oldEn, newEn})
		}
	} else if !new.Enabled {
		// First save with enabled=false is noteworthy
		t := "true"
		diffs = append(diffs, fieldDiff{"enabled", &t, boolStr(new.Enabled)})
	}

	for _, d := range diffs {
		if _, err := r.DB.Exec(`
			INSERT INTO rule_config_history (rule_name, field, old_value, new_value)
			VALUES (?, ?, ?, ?)
		`, ruleName, d.name, d.oldValue, d.newValue); err != nil {
			return err
		}
	}
	return nil
}

// ptrStrEq returns true when both pointers are nil or both point to equal strings.
func ptrStrEq(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}
