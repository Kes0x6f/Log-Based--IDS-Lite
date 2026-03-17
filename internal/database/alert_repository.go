package database

import (
	"database/sql"

	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

type AlertRepository struct {
	DB *sql.DB
}

func (r *AlertRepository) Insert(alert *model.Alert) error {
	query := `
    INSERT INTO alerts (
        id, timestamp, rule_name, severity, category,
        message, source_ip, username, host, event_count
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `

	_, err := r.DB.Exec(query,
		alert.ID,
		alert.Timestamp,
		alert.RuleName,
		alert.Severity,
		alert.Category,
		alert.Message,
		alert.SourceIP,
		alert.Username,
		alert.Host,
		alert.EventCount,
	)

	return err
}
