package database

import "database/sql"

func CreateTables(db *sql.DB) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS alerts (
			id TEXT PRIMARY KEY,
			timestamp DATETIME,

			rule_name TEXT,
			severity TEXT,
			category TEXT,

			message TEXT,

			source_ip TEXT,
			username TEXT,
			host TEXT,

			event_count INTEGER
		);`,

		`CREATE INDEX IF NOT EXISTS idx_alert_ip       ON alerts(source_ip);`,
		`CREATE INDEX IF NOT EXISTS idx_alert_time     ON alerts(timestamp);`,
		`CREATE INDEX IF NOT EXISTS idx_alert_severity ON alerts(severity);`,
		`CREATE INDEX IF NOT EXISTS idx_alert_category ON alerts(category);`,

		// Persistent key/value store for webhook URL, retention days, etc.
		`CREATE TABLE IF NOT EXISTS settings (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL DEFAULT ''
		);`,
	}

	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			return err
		}
	}

	return nil
}
