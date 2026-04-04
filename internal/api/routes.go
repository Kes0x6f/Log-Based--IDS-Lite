package api

import "net/http"

func NewRouter(handler *Handler) http.Handler {

	mux := http.NewServeMux()

	mux.HandleFunc("/alerts", handler.GetAlerts)
	mux.HandleFunc("/alerts/recent", handler.GetRecentAlerts)
	mux.HandleFunc("/alerts/count", handler.GetAlertCount)
	mux.HandleFunc("/alerts/severity-count", handler.GetSeverityCount)
	mux.HandleFunc("/stream/logs", handler.StreamLogs)
	mux.HandleFunc("/alerts/unique-ips", handler.GetUniqueIPCount)
	//dashboard

	fs := http.FileServer(http.Dir("web"))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		if r.URL.Path == "/" {
			http.ServeFile(w, r, "web/index.html")
			return
		}

		// Serve static files (css/js)
		fs.ServeHTTP(w, r)
	})

	mux.HandleFunc("/live", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/live.html")
	})

	return mux
}
