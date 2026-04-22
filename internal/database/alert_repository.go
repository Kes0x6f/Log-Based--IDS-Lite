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

func (r *AlertRepository) GetRecent(limit int) ([]model.Alert, error) {
	query := `
	SELECT id, timestamp, rule_name, severity, category,
	       message, source_ip, username, host, event_count
	FROM alerts
	ORDER BY timestamp DESC
	LIMIT ?
	`

	rows, err := r.DB.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []model.Alert

	for rows.Next() {
		var a model.Alert
		err := rows.Scan(
			&a.ID,
			&a.Timestamp,
			&a.RuleName,
			&a.Severity,
			&a.Category,
			&a.Message,
			&a.SourceIP,
			&a.Username,
			&a.Host,
			&a.EventCount,
		)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}

	return alerts, nil
}

func (r *AlertRepository) GetAlerts(ip, severity string, limit int) ([]model.Alert, error) {

	query := `
	SELECT id, timestamp, rule_name, severity, category,
	       message, source_ip, username, host, event_count
	FROM alerts
	WHERE 1=1
	`

	args := []interface{}{}

	if ip != "" {
		query += " AND source_ip = ?"
		args = append(args, ip)
	}

	if severity != "" {
		query += " AND severity = ?"
		args = append(args, severity)
	}

	query += " ORDER BY timestamp DESC"

	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	rows, err := r.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []model.Alert

	for rows.Next() {
		var a model.Alert
		err := rows.Scan(
			&a.ID,
			&a.Timestamp,
			&a.RuleName,
			&a.Severity,
			&a.Category,
			&a.Message,
			&a.SourceIP,
			&a.Username,
			&a.Host,
			&a.EventCount,
		)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}

	return alerts, nil
}

func (r *AlertRepository) CountAlerts() (int, error) {
	query := `SELECT COUNT(*) FROM alerts`

	var count int
	err := r.DB.QueryRow(query).Scan(&count)
	return count, err
}

func (r *AlertRepository) CountBySeverity(severity string) (int, error) {
	query := `SELECT COUNT(*) FROM alerts WHERE severity = ?`

	var count int
	err := r.DB.QueryRow(query, severity).Scan(&count)
	return count, err
}

func (r *AlertRepository) CountUniqueIPs() (int, error) {
	query := `SELECT COUNT(DISTINCT source_ip) FROM alerts WHERE source_ip != ''`

	var count int
	err := r.DB.QueryRow(query).Scan(&count)
	return count, err
}

func (r *AlertRepository) UpdateEventCount(id string, count int) error {
	query := `UPDATE alerts SET event_count = ? WHERE id = ?`
	_, err := r.DB.Exec(query, count, id)
	return err
}
