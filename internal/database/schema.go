package database

import "database/sql"

func CreateTables(db *sql.DB) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS alerts (
			id TEXT PRIMARY KEY,
			timestamp DATETIME,

			rule_name TEXT,
			severity  TEXT,
			category  TEXT,

			message   TEXT,

			source_ip  TEXT,
			username   TEXT,
			host       TEXT,

			-- Extended context fields 
			port       TEXT,
			command    TEXT,
			log_source TEXT,
			raw_line   TEXT,

			event_count INTEGER

			
			fail_count      INTEGER DEFAULT 0,
			ip_count        INTEGER DEFAULT 0,
			attack_duration INTEGER DEFAULT 0,
			target_user     TEXT    DEFAULT '',
			auth_method     TEXT    DEFAULT '',
			port_list       TEXT    DEFAULT '',
			caller_exe      TEXT    DEFAULT '',
			threat_detail   TEXT    DEFAULT ''
		);`,

		`CREATE INDEX IF NOT EXISTS idx_alert_ip         ON alerts(source_ip);`,
		`CREATE INDEX IF NOT EXISTS idx_alert_time       ON alerts(timestamp);`,
		`CREATE INDEX IF NOT EXISTS idx_alert_severity   ON alerts(severity);`,
		`CREATE INDEX IF NOT EXISTS idx_alert_category   ON alerts(category);`,

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

	// ── Migration: add new columns to existing databases ─────────────────────
	// SQLite does not support IF NOT EXISTS on ALTER TABLE, so we attempt each
	// column addition and silently ignore "duplicate column" errors. This is
	// safe to run on every startup — it is a no-op once the columns exist.
	migrations := []string{
		`ALTER TABLE alerts ADD COLUMN port       TEXT DEFAULT ''`,
		`ALTER TABLE alerts ADD COLUMN command    TEXT DEFAULT ''`,
		`ALTER TABLE alerts ADD COLUMN log_source TEXT DEFAULT ''`,
		`ALTER TABLE alerts ADD COLUMN raw_line   TEXT DEFAULT ''`,

		`ALTER TABLE alerts ADD COLUMN fail_count      INTEGER DEFAULT 0`,
		`ALTER TABLE alerts ADD COLUMN ip_count        INTEGER DEFAULT 0`,
		`ALTER TABLE alerts ADD COLUMN attack_duration INTEGER DEFAULT 0`,
		`ALTER TABLE alerts ADD COLUMN target_user     TEXT    DEFAULT ''`,
		`ALTER TABLE alerts ADD COLUMN auth_method     TEXT    DEFAULT ''`,
		`ALTER TABLE alerts ADD COLUMN port_list       TEXT    DEFAULT ''`,
		`ALTER TABLE alerts ADD COLUMN caller_exe      TEXT    DEFAULT ''`,
		`ALTER TABLE alerts ADD COLUMN threat_detail   TEXT    DEFAULT ''`,
	}

	for _, m := range migrations {
		if _, err := db.Exec(m); err != nil {
			// "duplicate column name" is the expected error when the column
			// already exists — any other error is a real problem.
			if !isDuplicateColumnError(err) {
				return err
			}
		}
	}

	// Create indexes after migrations guarantee columns exist on both new
	// and upgraded databases.
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_alert_log_source ON alerts(log_source)`,
		`CREATE INDEX IF NOT EXISTS idx_alert_target_user ON alerts(target_user)`,
	}

	for _, idx := range indexes {
		if _, err := db.Exec(idx); err != nil {
			return err
		}
	}

	return nil
}

// isDuplicateColumnError returns true when SQLite reports that a column
// already exists, which happens when ALTER TABLE ADD COLUMN is run a
// second time on a database that was already migrated.
func isDuplicateColumnError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return len(msg) >= 21 && msg[:21] == "duplicate column name"
}
