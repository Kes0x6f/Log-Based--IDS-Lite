package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/collector"
	"github.com/Kes0x6f/Log-Based--IDS/internal/database"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/stream"
)

type Handler struct {
	Repo           *database.AlertRepository
	SettingsRepo   *database.SettingsRepository
	Broadcaster    *stream.Broadcaster
	Stats          *collector.SourceStats
	RuleConfigRepo *database.RuleConfigRepository
	Engine         *detection.Engine
}

// ── /alerts ───────────────────────────────────────────────────────────────────

// GetAlerts handles GET /alerts with optional query params:
//
//	ip, severity, category, rule, since (RFC3339), limit
func (h *Handler) GetAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	ip := q.Get("ip")
	severity := q.Get("severity")
	category := q.Get("category")
	rule := q.Get("rule")
	since := q.Get("since")

	limit := 100
	if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 {
		limit = l
	}

	alerts, err := h.Repo.GetAlerts(ip, severity, category, rule, since, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonOK(w, alerts)
}

// GetRecentAlerts handles GET /alerts/recent?limit=N
func (h *Handler) GetRecentAlerts(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 {
		limit = l
	}

	alerts, err := h.Repo.GetRecent(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonOK(w, alerts)
}

// GetAlertByID handles GET /alerts/detail?id=ALT-xxx
//
// Replaces the client-side full-table scan in alert-detail.html.
func (h *Handler) GetAlertByID(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}

	alert, err := h.Repo.GetByID(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if alert == nil {
		http.Error(w, "alert not found", http.StatusNotFound)
		return
	}

	jsonOK(w, alert)
}

// GetAlertCount handles GET /alerts/count
func (h *Handler) GetAlertCount(w http.ResponseWriter, r *http.Request) {
	count, err := h.Repo.CountAlerts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]int{"count": count})
}

// GetSeverityCount handles GET /alerts/severity-count?severity=HIGH
func (h *Handler) GetSeverityCount(w http.ResponseWriter, r *http.Request) {
	severity := r.URL.Query().Get("severity")
	if severity == "" {
		http.Error(w, "severity is required", http.StatusBadRequest)
		return
	}

	count, err := h.Repo.CountBySeverity(severity)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]int{"count": count})
}

// GetUniqueIPCount handles GET /alerts/unique-ips
func (h *Handler) GetUniqueIPCount(w http.ResponseWriter, r *http.Request) {
	count, err := h.Repo.CountUniqueIPs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]int{"count": count})
}

// CountAlertsBefore handles GET /alerts/count-before?days=N
//
// Returns the number of alerts older than N days so the Settings prune-check
// button can show a real count before the user commits to deleting.
func (h *Handler) CountAlertsBefore(w http.ResponseWriter, r *http.Request) {
	daysStr := r.URL.Query().Get("days")
	days, err := strconv.Atoi(daysStr)
	if err != nil || days <= 0 {
		http.Error(w, "days must be a positive integer", http.StatusBadRequest)
		return
	}
	before := time.Now().AddDate(0, 0, -days)
	count, err := h.Repo.CountOlderThan(before)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]int64{"count": count})
}

// PruneAlerts handles DELETE /alerts/prune
//
// Query params (one of):
//
//	days=30   — delete everything older than N days
//	before=<RFC3339> — delete everything before the given timestamp
//
// Powers the "prune now" button in Settings › Data Retention.
func (h *Handler) PruneAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	var before time.Time

	if d := q.Get("days"); d != "" {
		days, err := strconv.Atoi(d)
		if err != nil || days <= 0 {
			http.Error(w, "days must be a positive integer", http.StatusBadRequest)
			return
		}
		before = time.Now().AddDate(0, 0, -days)
	} else if b := q.Get("before"); b != "" {
		var err error
		before, err = time.Parse(time.RFC3339, b)
		if err != nil {
			http.Error(w, "before must be an RFC3339 timestamp", http.StatusBadRequest)
			return
		}
	} else {
		http.Error(w, "provide days or before", http.StatusBadRequest)
		return
	}

	deleted, err := h.Repo.PruneOlderThan(before)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]int64{"deleted": deleted})
}

// DeleteAllAlerts handles DELETE /alerts/all
//
// Powers the "delete all alerts" button in the Settings danger-zone.
func (h *Handler) DeleteAllAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	deleted, err := h.Repo.DeleteAll()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]int64{"deleted": deleted})
}

// ── /stream/logs ──────────────────────────────────────────────────────────────

// StreamLogs handles GET /stream/logs (Server-Sent Events).
//
// Each SSE message is now formatted as "source|line" so live.html
// can colour by source without content heuristics.  An optional ?source=auth
// query param lets the client receive only one source's lines.
func (h *Handler) StreamLogs(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	sourceFilter := r.URL.Query().Get("source") // optional; empty = all sources

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := h.Broadcaster.Subscribe()
	defer h.Broadcaster.Unsubscribe(ch)

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			if sourceFilter != "" && msg.Source != sourceFilter {
				continue
			}
			// Format: "source|line" — frontend splits on first "|"
			fmt.Fprintf(w, "data: %s|%s\n\n", msg.Source, msg.Line)
			flusher.Flush()
		}
	}
}

// TestWebhook handles POST /settings/test-webhook
//
// Sends a synthetic test payload to the configured webhook URL so the user
// can verify their endpoint is reachable without waiting for a real alert.
func (h *Handler) TestWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.SettingsRepo == nil {
		http.Error(w, "settings storage not configured", http.StatusServiceUnavailable)
		return
	}

	webhookURL, err := h.SettingsRepo.Get("webhook-url")
	if err != nil || webhookURL == "" {
		http.Error(w, "no webhook URL configured", http.StatusBadRequest)
		return
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"id":          "ALT-test-00000000-0000-0000-0000-000000000000",
		"timestamp":   time.Now(),
		"rule":        "Test Webhook",
		"severity":    "HIGH",
		"category":    "test",
		"message":     "This is a test notification from Log-IDS.",
		"source_ip":   "0.0.0.0",
		"username":    "test",
		"host":        "localhost",
		"event_count": 1,
	})

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(webhookURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		http.Error(w, "webhook POST failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	jsonOK(w, map[string]interface{}{"status": resp.StatusCode, "url": webhookURL})
}

// ── /sources/status ───────────────────────────────────────────────────────────

// GetSourceStatus handles GET /sources/status
//
// Returns live collector statistics so sources.html can show real
// health instead of guessing from alert timestamps.
func (h *Handler) GetSourceStatus(w http.ResponseWriter, r *http.Request) {
	if h.Stats == nil {
		jsonOK(w, map[string]interface{}{})
		return
	}
	jsonOK(w, h.Stats.Snapshot())
}

// ── /settings ─────────────────────────────────────────────────────────────────

// GetSettings handles GET /settings — returns all persisted key/value pairs.
func (h *Handler) GetSettings(w http.ResponseWriter, r *http.Request) {
	if h.SettingsRepo == nil {
		jsonOK(w, map[string]string{})
		return
	}
	all, err := h.SettingsRepo.GetAll()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, all)
}

// UpdateSetting handles POST /settings — upserts one key/value pair.
//
// Expects JSON body: {"key":"webhook-url","value":"https://…"}

func (h *Handler) UpdateSetting(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.SettingsRepo == nil {
		http.Error(w, "settings storage not configured", http.StatusServiceUnavailable)
		return
	}

	var body struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if body.Key == "" {
		http.Error(w, "key is required", http.StatusBadRequest)
		return
	}

	if err := h.SettingsRepo.Set(body.Key, body.Value); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// For global sensitivity keys, invalidate the engine cache immediately so
	// the change takes effect on the next event rather than waiting for the TTL.
	sensitivityKeys := map[string]bool{
		"global-threshold-mul": true,
		"global-window-sec":    true,
		"global-cooldown-sec":  true,
	}
	if sensitivityKeys[body.Key] && h.Engine != nil {
		h.Engine.InvalidateCache()
	}

	jsonOK(w, map[string]string{"key": body.Key, "value": body.Value})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func jsonOK(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// ── /rules ────────────────────────────────────────────────────────────────────

// GetRuleList handles GET /rules
//
// Returns every registered rule with its compiled defaults, any active DB
// override, the merged effective config, the enabled flag, and aggregate
// alert stats.
func (h *Handler) GetRuleList(w http.ResponseWriter, r *http.Request) {
	if h.Engine == nil {
		http.Error(w, "engine not available", http.StatusServiceUnavailable)
		return
	}

	metas := h.Engine.DescribeAll()

	overrides := map[string]database.RuleConfig{}
	if h.RuleConfigRepo != nil {
		var err error
		overrides, err = h.RuleConfigRepo.GetAll()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Non-fatal: if stats fail we just show zero counts.
	ruleStats, _ := h.Repo.RuleStats()

	type limitsShape struct {
		Threshold   int `json:"threshold"`
		WindowSec   int `json:"window_sec"`
		CooldownSec int `json:"cooldown_sec"`
	}
	type overrideShape struct {
		Threshold   *int `json:"threshold"`
		WindowSec   *int `json:"window_sec"`
		CooldownSec *int `json:"cooldown_sec"`
	}
	type ruleRow struct {
		Name        string        `json:"name"`
		LogSource   string        `json:"log_source"`
		Program     string        `json:"program"`
		Description string        `json:"description"`
		Defaults    limitsShape   `json:"defaults"`
		Override    overrideShape `json:"override"`
		Effective   limitsShape   `json:"effective"`
		Enabled     bool          `json:"enabled"`
		FireCount   int           `json:"fire_count"`
		LastFired   *time.Time    `json:"last_fired"`
	}

	result := make([]ruleRow, 0, len(metas))
	for _, meta := range metas {
		cfg := h.Engine.Resolve(meta)

		var ov overrideShape
		if o, ok := overrides[meta.DisplayName]; ok {
			ov.Threshold = o.Threshold
			ov.WindowSec = o.WindowSec
			ov.CooldownSec = o.CooldownSec
		}

		var fireCount int
		var lastFired *time.Time
		if s, ok := ruleStats[meta.DisplayName]; ok {
			fireCount = s.Count
			lastFired = s.LastFired
		}

		result = append(result, ruleRow{
			Name:        meta.DisplayName,
			LogSource:   meta.LogSource,
			Program:     meta.Program,
			Description: meta.Description,
			Defaults: limitsShape{
				Threshold:   meta.Defaults.Threshold,
				WindowSec:   meta.Defaults.WindowSec,
				CooldownSec: meta.Defaults.CooldownSec,
			},
			Override: ov,
			Effective: limitsShape{
				Threshold:   cfg.Threshold,
				WindowSec:   int(cfg.Window.Seconds()),
				CooldownSec: int(cfg.Cooldown.Seconds()),
			},
			Enabled:   cfg.Enabled,
			FireCount: fireCount,
			LastFired: lastFired,
		})
	}

	jsonOK(w, result)
}

// ── /rule-configs ─────────────────────────────────────────────────────────────

// GetRuleConfigMap handles GET /rule-configs
//
// Returns every row in rule_config as a name→config map.
func (h *Handler) GetRuleConfigMap(w http.ResponseWriter, r *http.Request) {
	if h.RuleConfigRepo == nil {
		jsonOK(w, map[string]interface{}{})
		return
	}
	all, err := h.RuleConfigRepo.GetAll()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, all)
}

// UpsertRuleConfig handles POST /rule-configs
//
// Inserts or replaces a rule's config row. Omit (send null for) any field you want to leave at its compiled default.
func (h *Handler) UpsertRuleConfig(w http.ResponseWriter, r *http.Request) {
	if h.RuleConfigRepo == nil {
		http.Error(w, "rule config repo not available", http.StatusServiceUnavailable)
		return
	}

	var body struct {
		RuleName    string `json:"rule_name"`
		Threshold   *int   `json:"threshold"`
		WindowSec   *int   `json:"window_sec"`
		CooldownSec *int   `json:"cooldown_sec"`
		Enabled     bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.RuleName == "" {
		http.Error(w, "rule_name is required", http.StatusBadRequest)
		return
	}
	if body.Threshold != nil && *body.Threshold < 1 {
		http.Error(w, "threshold must be >= 1", http.StatusBadRequest)
		return
	}
	if body.WindowSec != nil && *body.WindowSec < 10 {
		http.Error(w, "window_sec must be >= 10 seconds", http.StatusBadRequest)
		return
	}
	if body.CooldownSec != nil && *body.CooldownSec < 0 {
		http.Error(w, "cooldown_sec must be >= 0", http.StatusBadRequest)
		return
	}

	cfg := database.RuleConfig{
		RuleName:    body.RuleName,
		Threshold:   body.Threshold,
		WindowSec:   body.WindowSec,
		CooldownSec: body.CooldownSec,
		Enabled:     body.Enabled,
	}
	if err := h.RuleConfigRepo.Upsert(cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if h.Engine != nil {
		h.Engine.InvalidateCache()
	}

	jsonOK(w, map[string]string{"status": "saved", "rule_name": body.RuleName})
}

// ResetRuleConfig handles DELETE /rule-configs?rule=...
// Removes a single rule's override row, reverting it to compiled defaults.
func (h *Handler) ResetRuleConfig(w http.ResponseWriter, r *http.Request) {
	if h.RuleConfigRepo == nil {
		http.Error(w, "rule config repo not available", http.StatusServiceUnavailable)
		return
	}

	ruleName := r.URL.Query().Get("rule")
	if ruleName == "" {
		http.Error(w, "rule query parameter is required", http.StatusBadRequest)
		return
	}

	if err := h.RuleConfigRepo.Reset(ruleName); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if h.Engine != nil {
		h.Engine.InvalidateCache()
	}

	jsonOK(w, map[string]string{"status": "reset", "rule_name": ruleName})
}

// ResetAllRuleConfigs handles DELETE /rule-configs (no rule param)
// Removes every override row, reverting all rules to compiled defaults.
func (h *Handler) ResetAllRuleConfigs(w http.ResponseWriter, r *http.Request) {
	if h.RuleConfigRepo == nil {
		http.Error(w, "rule config repo not available", http.StatusServiceUnavailable)
		return
	}

	if err := h.RuleConfigRepo.ResetAll(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if h.Engine != nil {
		h.Engine.InvalidateCache()
	}

	jsonOK(w, map[string]string{"status": "all overrides removed"})
}

func (h *Handler) GetRuleConfigHistory(w http.ResponseWriter, r *http.Request) {
	if h.RuleConfigRepo == nil {
		jsonOK(w, []interface{}{})
		return
	}

	ruleName := r.URL.Query().Get("rule")
	if ruleName == "" {
		http.Error(w, "rule query parameter is required", http.StatusBadRequest)
		return
	}

	limit := 10
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}

	history, err := h.RuleConfigRepo.GetHistory(ruleName, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if history == nil {
		history = []database.RuleConfigHistory{}
	}

	jsonOK(w, history)
}

// ── /rule-configs/simulate ────────────────────────────────────────────────────

// SimulateRuleConfig handles POST /rule-configs/simulate
//
// Estimates how many alerts would have fired in the lookback window if the
// proposed config had been active. Uses stored alert history as a proxy for
// raw events — see warnings in the response for limitations.
//
//	Threshold simulation: counts alerts where EventCount ≥ proposed_threshold.
//	                      Underestimates for threshold decreases because events
//	                      below the original threshold were never stored.
//	Cooldown simulation:  walks alerts chronologically and applies the new
//	                      cooldown gap. Accurate for cooldown-only changes.
//	Window simulation:    cannot be estimated from alert data; a warning is
//	                      returned and the field is otherwise ignored.
func (h *Handler) SimulateRuleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		RuleName      string `json:"rule_name"`
		Threshold     *int   `json:"threshold"`
		WindowSec     *int   `json:"window_sec"`
		CooldownSec   *int   `json:"cooldown_sec"`
		LookbackHours int    `json:"lookback_hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.RuleName == "" {
		http.Error(w, "rule_name is required", http.StatusBadRequest)
		return
	}
	if body.Threshold != nil && *body.Threshold < 1 {
		http.Error(w, "threshold must be >= 1", http.StatusBadRequest)
		return
	}
	if body.LookbackHours <= 0 || body.LookbackHours > 168 {
		body.LookbackHours = 24
	}

	// ── Look up compiled default threshold for the comparison warning ────────
	compiledThreshold := 0
	if h.Engine != nil {
		for _, meta := range h.Engine.DescribeAll() {
			if meta.DisplayName == body.RuleName {
				compiledThreshold = meta.Defaults.Threshold
				break
			}
		}
	}

	// ── Fetch alert history for this rule ────────────────────────────────────
	since := time.Now().Add(-time.Duration(body.LookbackHours) * time.Hour)
	sinceStr := since.Format(time.RFC3339)

	alerts, err := h.Repo.GetAlerts("", "", "", body.RuleName, sinceStr, 10000)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	actualCount := len(alerts)
	var warnings []string

	// ── Step 1: threshold filter ──────────────────────────────────────────────
	// Keep only alerts whose EventCount reaches the proposed threshold.
	// alerts is sorted DESC from the DB; preserve order for the cooldown walk.
	candidates := alerts
	if body.Threshold != nil {
		newT := *body.Threshold
		n := 0
		for _, a := range alerts {
			if a.EventCount >= newT {
				alerts[n] = a
				n++
			}
		}
		candidates = alerts[:n]

		// If the new threshold is lower than (or equal to) the compiled default,
		// there may be raw events between stored alerts that would now also fire
		// but are invisible to us.
		if compiledThreshold == 0 || newT <= compiledThreshold {
			warnings = append(warnings,
				"Lowering or matching the compiled threshold may produce more alerts "+
					"than shown — events that fell below the original threshold "+
					"were never stored and cannot be counted.")
		}
	}

	// ── Step 2: cooldown simulation ───────────────────────────────────────────
	// Walk candidates in chronological order (reverse of DESC-sorted slice)
	// and apply the proposed cooldown gap between consecutive alerts.
	simulated := len(candidates)
	if body.CooldownSec != nil {
		newCooldown := time.Duration(*body.CooldownSec) * time.Second
		fires := 0
		var lastFire time.Time
		for i := len(candidates) - 1; i >= 0; i-- {
			a := candidates[i]
			if lastFire.IsZero() || a.Timestamp.Sub(lastFire) >= newCooldown {
				fires++
				lastFire = a.Timestamp
			}
		}
		simulated = fires
		if newCooldown == 0 {
			warnings = append(warnings,
				"Cooldown of 0 seconds means every event fires a new alert — "+
					"this may produce very high alert volume during attacks.")
		}
	}

	// ── Step 3: window note ───────────────────────────────────────────────────
	if body.WindowSec != nil {
		warnings = append(warnings,
			"Window changes cannot be simulated from alert history — "+
				"raw per-event timestamps are required for accurate results. "+
				"Save the change and monitor live behaviour instead.")
	}

	// ── Build response ────────────────────────────────────────────────────────
	delta := simulated - actualCount
	deltaStr := fmt.Sprintf("%+d", delta)
	if delta == 0 {
		deltaStr = "±0"
	}

	resp := map[string]interface{}{
		"rule_name":             body.RuleName,
		"lookback_hours":        body.LookbackHours,
		"actual_alert_count":    actualCount,
		"simulated_alert_count": simulated,
		"delta":                 deltaStr,
	}
	if len(warnings) > 0 {
		resp["warnings"] = warnings
	} else {
		resp["warnings"] = []string{}
	}

	jsonOK(w, resp)
}

// ── helpers ───────────────────────────────────────────────────────────────────
// (keep existing jsonOK below)
