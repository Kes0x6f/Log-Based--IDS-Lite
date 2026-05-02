package alert

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/database"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// severityOrder maps severity labels to an integer rank so we can compare
// "is this alert severe enough to notify?" in one line.
var severityOrder = map[model.Severity]int{
	model.SeverityLow:      1,
	model.SeverityMedium:   2,
	model.SeverityHigh:     3,
	model.SeverityCritical: 4,
}

type Manager struct {
	AlertRepo    *database.AlertRepository
	SettingsRepo *database.SettingsRepository // nil-safe; webhooks disabled when nil

	dedupMu sync.Mutex
	dedup   map[string]time.Time // key = RuleName|SourceIP → last fired time
}

func (m *Manager) Start(input <-chan *model.Alert) {
	m.dedup = make(map[string]time.Time)

	// Periodically evict stale dedup entries so the map doesn't grow forever.
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			m.cleanDedup()
		}
	}()

	for alert := range input {
		if alert.IsUpdate {
			if err := m.AlertRepo.UpdateEventCount(alert.OriginalAlertID, alert.EventCount); err != nil {
				log.Println("Update alert count error:", err)
			}
			continue
		}

		if err := m.AlertRepo.Insert(alert); err != nil {
			log.Println("Insert alert error:", err)
			continue
		}

		log.Println("ALERT:", alert.Message)

		// Enforce max-rows cap if configured.
		go m.enforceMaxRows()

		// Webhook dispatch is fire-and-forget; we never block the alert pipeline.
		if m.SettingsRepo != nil {
			go m.maybeFireWebhook(alert)
		}
	}
}

// maybeFireWebhook reads the current settings on every call so changes made
// in the Settings page take effect immediately without restarting the daemon.
func (m *Manager) maybeFireWebhook(alert *model.Alert) {
	// ── 1. Webhook URL ───────────────────────────────────────────────────────
	webhookURL, err := m.SettingsRepo.Get("webhook-url")
	if err != nil || webhookURL == "" {
		return
	}

	// ── 2. Minimum severity threshold ────────────────────────────────────────
	minSevStr, _ := m.SettingsRepo.Get("notify-sev")
	if minSevStr == "" {
		minSevStr = "CRITICAL"
	}
	minSev := model.Severity(minSevStr)
	if severityOrder[alert.Severity] < severityOrder[minSev] {
		return
	}

	// ── 3. Deduplication window ──────────────────────────────────────────────
	dedupSecsStr, _ := m.SettingsRepo.Get("notify-dedup")
	dedupSecs := 300 // default: 5 minutes
	if dedupSecsStr != "" {
		if n, e := strconv.Atoi(dedupSecsStr); e == nil && n >= 0 {
			dedupSecs = n
		}
	}
	dedupWindow := time.Duration(dedupSecs) * time.Second

	dedupKey := alert.RuleName + "|" + alert.SourceIP
	m.dedupMu.Lock()
	if last, ok := m.dedup[dedupKey]; ok && time.Since(last) < dedupWindow {
		m.dedupMu.Unlock()
		return // suppressed — same rule+IP fired recently
	}
	m.dedup[dedupKey] = time.Now()
	m.dedupMu.Unlock()

	// ── 4. Build and send the payload ────────────────────────────────────────
	payload, err := json.Marshal(map[string]interface{}{
		"id":          alert.ID,
		"timestamp":   alert.Timestamp,
		"rule":        alert.RuleName,
		"severity":    alert.Severity,
		"category":    alert.Category,
		"message":     alert.Message,
		"source_ip":   alert.SourceIP,
		"username":    alert.Username,
		"host":        alert.Host,
		"event_count": alert.EventCount,
	})
	if err != nil {
		log.Println("Webhook marshal error:", err)
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(webhookURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Printf("Webhook POST error (%s): %v", alert.RuleName, err)
		return
	}
	defer resp.Body.Close()
	log.Printf("Webhook fired for %q → HTTP %d", alert.RuleName, resp.StatusCode)
}

// enforceMaxRows reads the max-rows setting and prunes the oldest alerts if
// the total count exceeds the cap. Called after every insert; no-op when
// SettingsRepo is nil or max-rows is 0 (no limit).
func (m *Manager) enforceMaxRows() {
	if m.SettingsRepo == nil {
		return
	}
	maxStr, err := m.SettingsRepo.Get("max-rows")
	if err != nil || maxStr == "" || maxStr == "0" {
		return
	}
	maxRows, err := strconv.ParseInt(maxStr, 10, 64)
	if err != nil || maxRows <= 0 {
		return
	}
	count, err := m.AlertRepo.CountAlerts()
	if err != nil || int64(count) <= maxRows {
		return
	}
	// Prune enough rows to get back under the cap.
	excess := int64(count) - maxRows
	deleted, err := m.AlertRepo.PruneOldestN(excess)
	if err != nil {
		log.Printf("enforceMaxRows: prune error: %v", err)
		return
	}
	if deleted > 0 {
		log.Printf("enforceMaxRows: pruned %d alert(s) to stay under %d-row cap", deleted, maxRows)
	}
}

// cleanDedup evicts dedup entries that are older than 24 hours.
func (m *Manager) cleanDedup() {
	cutoff := time.Now().Add(-24 * time.Hour)
	m.dedupMu.Lock()
	defer m.dedupMu.Unlock()
	for k, t := range m.dedup {
		if t.Before(cutoff) {
			delete(m.dedup, k)
		}
	}
}
