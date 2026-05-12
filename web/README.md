# IDS frontend: CSS separated from HTML

This folder separates the inline CSS from each HTML page.

## Structure

- `*.html` contains the page markup and the existing JavaScript blocks.
- `css/*.css` contains the CSS extracted from each matching HTML page.
- `js/app.js` is copied unchanged from the uploaded files. JavaScript separation can be done next.
- `css/legacy-web.css` is the originally uploaded external CSS file, kept as a reference. It is not linked by the separated HTML pages because the inline CSS was more complete.

## Mapping

- `index.html` -> `css/index.css`
- `alerts.html` -> `css/alerts.css`
- `alert-detail.html` -> `css/alert-detail.css`
- `brute-force.html` -> `css/brute-force.css`
- `ip-profile.html` -> `css/ip-profile.css`
- `live.html` -> `css/live.css`
- `reports.html` -> `css/reports.css`
- `rules.html` -> `css/rules.css`
- `settings.html` -> `css/settings.css`
- `sources.html` -> `css/sources.css`
- `timeline.html` -> `css/timeline.css`

## Go server note

If your Go backend only serves `/web.css`, add a static handler for the CSS folder, for example:

```go
fs := http.FileServer(http.Dir("web/css"))
mux.Handle("/css/", http.StripPrefix("/css/", fs))
```

Keep the HTML files in the same `web/` directory and place the extracted CSS files under `web/css/`.
