package database

import (
	"database/sql"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

type AlertRepository struct {
	DB *sql.DB
}

type RuleStat struct {
	Count     int        `json:"count"`
	LastFired *time.Time `json:"last_fired"`
}

func (r *AlertRepository) Insert(alert *model.Alert) error {
	query := `
	INSERT INTO alerts (
		id, timestamp, rule_name, severity, category,
		message,
		source_ip, username, host,
		port, command, log_source, raw_line,
		event_count,
		fail_count, ip_count, attack_duration,
		target_user, auth_method, port_list, caller_exe, threat_detail
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
		alert.Port,
		alert.Command,
		alert.LogSource,
		alert.RawLine,
		alert.EventCount,

		alert.FailCount,
		alert.IPCount,
		alert.AttackDuration,
		alert.TargetUser,
		alert.AuthMethod,
		alert.PortList,
		alert.CallerExe,
		alert.ThreatDetail,
	)

	return err
}

// GetByID returns a single alert by its exact ID, or (nil, nil) when not found.
// Enables the alert-detail page to fetch one row instead of scanning 2000.
func (r *AlertRepository) GetByID(id string) (*model.Alert, error) {
	query := `
	SELECT id, timestamp, rule_name, severity, category,
	       message,
	       source_ip, username, host,
	       port, command, log_source, raw_line,
	       event_count,
		   fail_count, ip_count, attack_duration,
	       target_user, auth_method, port_list, caller_exe, threat_detail
	FROM alerts
	WHERE id = ?
	`

	var a model.Alert
	err := r.DB.QueryRow(query, id).Scan(
		&a.ID, &a.Timestamp, &a.RuleName, &a.Severity, &a.Category,
		&a.Message,
		&a.SourceIP, &a.Username, &a.Host,
		&a.Port, &a.Command, &a.LogSource, &a.RawLine,
		&a.EventCount,
		&a.FailCount, &a.IPCount, &a.AttackDuration,
		&a.TargetUser, &a.AuthMethod, &a.PortList, &a.CallerExe, &a.ThreatDetail,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

func (r *AlertRepository) GetRecent(limit int) ([]model.Alert, error) {
	query := `
	SELECT id, timestamp, rule_name, severity, category,
	       message,
	       source_ip, username, host,
	       port, command, log_source, raw_line,
	       event_count,
		   fail_count, ip_count, attack_duration,
	       target_user, auth_method, port_list, caller_exe, threat_detail
	FROM alerts
	ORDER BY timestamp DESC
	LIMIT ?
	`

	rows, err := r.DB.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanAlerts(rows)
}

// GetAlerts filters by ip, severity, category, rule, and/or since.
func (r *AlertRepository) GetAlerts(ip, severity, category, rule, since string, limit int) ([]model.Alert, error) {
	query := `
	SELECT id, timestamp, rule_name, severity, category,
	       message,
	       source_ip, username, host,
	       port, command, log_source, raw_line,
	       event_count,
		   fail_count, ip_count, attack_duration,
	       target_user, auth_method, port_list, caller_exe, threat_detail
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

	if category != "" {
		query += " AND category = ?"
		args = append(args, category)
	}

	if rule != "" {
		query += " AND rule_name = ?"
		args = append(args, rule)
	}

	if since != "" {
		t, err := time.Parse(time.RFC3339, since)
		if err == nil {
			query += " AND timestamp >= ?"
			args = append(args, t)
		}
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

	return scanAlerts(rows)
}

func (r *AlertRepository) CountAlerts() (int, error) {
	var count int
	err := r.DB.QueryRow(`SELECT COUNT(*) FROM alerts`).Scan(&count)
	return count, err
}

func (r *AlertRepository) CountBySeverity(severity string) (int, error) {
	var count int
	err := r.DB.QueryRow(`SELECT COUNT(*) FROM alerts WHERE severity = ?`, severity).Scan(&count)
	return count, err
}

func (r *AlertRepository) CountUniqueIPs() (int, error) {
	var count int
	err := r.DB.QueryRow(`SELECT COUNT(DISTINCT source_ip) FROM alerts WHERE source_ip != ''`).Scan(&count)
	return count, err
}

func (r *AlertRepository) UpdateEventCount(id string, count int) error {
	_, err := r.DB.Exec(`UPDATE alerts SET event_count = ? WHERE id = ?`, count, id)
	return err
}

// PruneOldestN deletes the N oldest alerts by timestamp.
// Used by the max-rows cap enforcement in Manager.
func (r *AlertRepository) PruneOldestN(n int64) (int64, error) {
	res, err := r.DB.Exec(`
		DELETE FROM alerts WHERE id IN (
			SELECT id FROM alerts ORDER BY timestamp ASC LIMIT ?
		)`, n)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CountOlderThan returns the number of alerts with a timestamp before `before`.
// Powers the GET /alerts/count-before endpoint used by the Settings prune check.
func (r *AlertRepository) CountOlderThan(before time.Time) (int64, error) {
	var count int64
	err := r.DB.QueryRow(`SELECT COUNT(*) FROM alerts WHERE timestamp < ?`, before).Scan(&count)
	return count, err
}

// PruneOlderThan deletes all alerts with a timestamp before `before` and
// returns the number of rows deleted.
// Change 6: powers the DELETE /alerts/prune endpoint used by the Settings page.
func (r *AlertRepository) PruneOlderThan(before time.Time) (int64, error) {
	res, err := r.DB.Exec(`DELETE FROM alerts WHERE timestamp < ?`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteAll removes every alert from the database.
// Powers the DELETE /alerts/all endpoint used by the Settings danger-zone.
func (r *AlertRepository) DeleteAll() (int64, error) {
	res, err := r.DB.Exec(`DELETE FROM alerts`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// scanAlerts is a shared helper that scans a *sql.Rows result into []model.Alert.
func scanAlerts(rows *sql.Rows) ([]model.Alert, error) {
	var alerts []model.Alert
	for rows.Next() {
		var a model.Alert
		err := rows.Scan(
			&a.ID, &a.Timestamp, &a.RuleName, &a.Severity, &a.Category,
			&a.Message,
			&a.SourceIP, &a.Username, &a.Host,
			&a.Port, &a.Command, &a.LogSource, &a.RawLine,
			&a.EventCount,
			&a.FailCount, &a.IPCount, &a.AttackDuration,
			&a.TargetUser, &a.AuthMethod, &a.PortList, &a.CallerExe, &a.ThreatDetail,
		)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

func (r *AlertRepository) RuleStats() (map[string]RuleStat, error) {
	rows, err := r.DB.Query(`
		SELECT rule_name, COUNT(*) AS cnt, MAX(timestamp) AS last_ts
		FROM   alerts
		GROUP  BY rule_name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]RuleStat)
	for rows.Next() {
		var name string
		var cnt int
		var ts time.Time
		if err := rows.Scan(&name, &cnt, &ts); err != nil {
			return nil, err
		}
		lf := ts
		out[name] = RuleStat{Count: cnt, LastFired: &lf}
	}
	return out, rows.Err()
}
