package database

import "database/sql"

// SettingsRepository persists key/value configuration in the settings table.
// Values are always stored as strings; the frontend is responsible for
// converting to typed values (numbers, booleans) before sending and after
// receiving.
type SettingsRepository struct {
	DB *sql.DB
}

// Get returns the stored value for key, or an empty string if the key does not exist.
func (r *SettingsRepository) Get(key string) (string, error) {
	var value string
	err := r.DB.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

// Set upserts a key/value pair.
func (r *SettingsRepository) Set(key, value string) error {
	_, err := r.DB.Exec(
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value,
	)
	return err
}

// GetAll returns every setting as a map so the frontend can load them in one request.
func (r *SettingsRepository) GetAll() (map[string]string, error) {
	rows, err := r.DB.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		result[k] = v
	}
	return result, rows.Err()
}
