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
	"github.com/Kes0x6f/Log-Based--IDS/internal/stream"
)

type Handler struct {
	Repo         *database.AlertRepository
	SettingsRepo *database.SettingsRepository
	Broadcaster  *stream.Broadcaster
	Stats        *collector.SourceStats
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
	jsonOK(w, map[string]string{"key": body.Key, "value": body.Value})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func jsonOK(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
