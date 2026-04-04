package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/Kes0x6f/Log-Based--IDS/internal/database"
	"github.com/Kes0x6f/Log-Based--IDS/internal/stream"
)

type Handler struct {
	Repo        *database.AlertRepository
	Broadcaster *stream.Broadcaster
}

func (h *Handler) GetAlerts(w http.ResponseWriter, r *http.Request) {

	ip := r.URL.Query().Get("ip")
	severity := r.URL.Query().Get("severity")

	limitStr := r.URL.Query().Get("limit")
	limit := 100 // default

	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}

	alerts, err := h.Repo.GetAlerts(ip, severity, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

func (h *Handler) GetRecentAlerts(w http.ResponseWriter, r *http.Request) {

	limitStr := r.URL.Query().Get("limit")
	limit := 20 // better default for dashboard

	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}

	alerts, err := h.Repo.GetRecent(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

func (h *Handler) StreamLogs(w http.ResponseWriter, r *http.Request) {
	fmt.Println("New SSE client connected")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := h.Broadcaster.Subscribe()

	ctx := r.Context()

	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		}
	}

}

func (h *Handler) GetAlertCount(w http.ResponseWriter, r *http.Request) {

	count, err := h.Repo.CountAlerts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]int{
		"count": count,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

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

	response := map[string]int{
		"count": count,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) GetUniqueIPCount(w http.ResponseWriter, r *http.Request) {

	count, err := h.Repo.CountUniqueIPs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]int{
		"count": count,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
