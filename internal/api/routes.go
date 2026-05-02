package api

import "net/http"

func NewRouter(handler *Handler) http.Handler {

	mux := http.NewServeMux()

	// ── Alert endpoints ───────────────────────────────────────────────────────
	mux.HandleFunc("/alerts", handler.GetAlerts)
	mux.HandleFunc("/alerts/recent", handler.GetRecentAlerts)
	mux.HandleFunc("/alerts/count", handler.GetAlertCount)
	mux.HandleFunc("/alerts/severity-count", handler.GetSeverityCount)
	mux.HandleFunc("/alerts/unique-ips", handler.GetUniqueIPCount)

	// Single-alert lookup for alert-detail.html
	mux.HandleFunc("/alerts/detail", handler.GetAlertByID)

	mux.HandleFunc("/alerts/count-before", handler.CountAlertsBefore)

	// Prune old alerts (DELETE /alerts/prune?days=30)
	mux.HandleFunc("/alerts/prune", handler.PruneAlerts)

	// Delete all alerts (DELETE /alerts/all)
	mux.HandleFunc("/alerts/all", handler.DeleteAllAlerts)

	// ── SSE stream ────────────────────────────────────────────────────────────
	// Now emits "source|line" frames; accepts optional ?source= filter
	mux.HandleFunc("/stream/logs", handler.StreamLogs)

	// ── Source health ─────────────────────────────────────────────────────────
	// Live collector statistics for sources.html
	mux.HandleFunc("/sources/status", handler.GetSourceStatus)

	// ── Settings ──────────────────────────────────────────────────────────────
	// Persistent settings for the settings page
	mux.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			handler.GetSettings(w, r)
		case "POST":
			handler.UpdateSetting(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/settings/test-webhook", handler.TestWebhook)

	// ── Static file serving ───────────────────────────────────────────────────
	fs := http.FileServer(http.Dir("web"))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, "web/index.html")
			return
		}
		fs.ServeHTTP(w, r)
	})

	mux.HandleFunc("/live", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/live.html")
	})

	return mux
}
