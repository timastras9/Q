package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// ScanRecord represents a stored scan in the database
type ScanRecord struct {
	ID              string          `json:"id"`
	UserID          string          `json:"user_id,omitempty"`
	Status          string          `json:"status"`
	Targets         string          `json:"targets"`
	Instruction     string          `json:"instruction,omitempty"`
	StartTime       time.Time       `json:"start_time"`
	EndTime         *time.Time      `json:"end_time,omitempty"`
	Recon           json.RawMessage `json:"recon,omitempty"`
	Vulnerabilities json.RawMessage `json:"vulnerabilities,omitempty"`
	Logs            json.RawMessage `json:"logs,omitempty"`
	InputTokens     int             `json:"input_tokens"`
	OutputTokens    int             `json:"output_tokens"`
	TotalCost       float64         `json:"total_cost"`
	CreatedAt       time.Time       `json:"created_at"`
}

// Store handles database operations for scan results
type Store struct {
	db *sql.DB
}

// NewStore creates a new storage connection
func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, err
	}

	return &Store{db: db}, nil
}

// Close closes the database connection
func (s *Store) Close() error {
	return s.db.Close()
}

// SaveScan stores a scan result in the database
func (s *Store) SaveScan(scan *ScanRecord) error {
	query := `
		INSERT INTO scans (id, user_id, status, targets, instruction, start_time, end_time,
			recon, vulnerabilities, logs, input_tokens, output_tokens, total_cost, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			status = excluded.status,
			end_time = excluded.end_time,
			recon = excluded.recon,
			vulnerabilities = excluded.vulnerabilities,
			logs = excluded.logs,
			input_tokens = excluded.input_tokens,
			output_tokens = excluded.output_tokens,
			total_cost = excluded.total_cost
	`

	_, err := s.db.Exec(query,
		scan.ID,
		scan.UserID,
		scan.Status,
		scan.Targets,
		scan.Instruction,
		scan.StartTime,
		scan.EndTime,
		scan.Recon,
		scan.Vulnerabilities,
		scan.Logs,
		scan.InputTokens,
		scan.OutputTokens,
		scan.TotalCost,
		scan.CreatedAt,
	)
	return err
}

// GetScan retrieves a scan by ID
func (s *Store) GetScan(id string) (*ScanRecord, error) {
	query := `
		SELECT id, user_id, status, targets, instruction, start_time, end_time,
			recon, vulnerabilities, logs, input_tokens, output_tokens, total_cost, created_at
		FROM scans WHERE id = ?
	`

	var scan ScanRecord
	var endTime sql.NullTime
	var recon, vulns, logs sql.NullString
	var userID, instruction sql.NullString

	err := s.db.QueryRow(query, id).Scan(
		&scan.ID,
		&userID,
		&scan.Status,
		&scan.Targets,
		&instruction,
		&scan.StartTime,
		&endTime,
		&recon,
		&vulns,
		&logs,
		&scan.InputTokens,
		&scan.OutputTokens,
		&scan.TotalCost,
		&scan.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	if userID.Valid {
		scan.UserID = userID.String
	}
	if instruction.Valid {
		scan.Instruction = instruction.String
	}
	if endTime.Valid {
		scan.EndTime = &endTime.Time
	}
	if recon.Valid {
		scan.Recon = json.RawMessage(recon.String)
	}
	if vulns.Valid {
		scan.Vulnerabilities = json.RawMessage(vulns.String)
	}
	if logs.Valid {
		scan.Logs = json.RawMessage(logs.String)
	}

	return &scan, nil
}

// UpdateScanStatus updates the status of a scan
func (s *Store) UpdateScanStatus(id, status string, endTime *time.Time) error {
	query := `UPDATE scans SET status = ?, end_time = ? WHERE id = ?`
	_, err := s.db.Exec(query, status, endTime, id)
	return err
}

// UpdateScanResults updates the results of a scan
func (s *Store) UpdateScanResults(id string, recon, vulnerabilities, logs json.RawMessage) error {
	query := `UPDATE scans SET recon = ?, vulnerabilities = ?, logs = ? WHERE id = ?`
	_, err := s.db.Exec(query, recon, vulnerabilities, logs, id)
	return err
}

// ListScans returns recent scans
func (s *Store) ListScans(limit int) ([]*ScanRecord, error) {
	query := `
		SELECT id, user_id, status, targets, instruction, start_time, end_time,
			recon, vulnerabilities, logs, input_tokens, output_tokens, total_cost, created_at
		FROM scans
		ORDER BY created_at DESC
		LIMIT ?
	`

	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []*ScanRecord
	for rows.Next() {
		var scan ScanRecord
		var endTime sql.NullTime
		var recon, vulns, logs sql.NullString
		var userID, instruction sql.NullString

		err := rows.Scan(
			&scan.ID,
			&userID,
			&scan.Status,
			&scan.Targets,
			&instruction,
			&scan.StartTime,
			&endTime,
			&recon,
			&vulns,
			&logs,
			&scan.InputTokens,
			&scan.OutputTokens,
			&scan.TotalCost,
			&scan.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		if userID.Valid {
			scan.UserID = userID.String
		}
		if instruction.Valid {
			scan.Instruction = instruction.String
		}
		if endTime.Valid {
			scan.EndTime = &endTime.Time
		}
		if recon.Valid {
			scan.Recon = json.RawMessage(recon.String)
		}
		if vulns.Valid {
			scan.Vulnerabilities = json.RawMessage(vulns.String)
		}
		if logs.Valid {
			scan.Logs = json.RawMessage(logs.String)
		}

		scans = append(scans, &scan)
	}

	return scans, nil
}

// ListScansByUser returns scans for a specific user
func (s *Store) ListScansByUser(userID string, limit int) ([]*ScanRecord, error) {
	query := `
		SELECT id, user_id, status, targets, instruction, start_time, end_time,
			recon, vulnerabilities, logs, input_tokens, output_tokens, total_cost, created_at
		FROM scans
		WHERE user_id = ?
		ORDER BY created_at DESC
		LIMIT ?
	`

	rows, err := s.db.Query(query, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []*ScanRecord
	for rows.Next() {
		var scan ScanRecord
		var endTime sql.NullTime
		var recon, vulns, logs sql.NullString
		var uid, instruction sql.NullString

		err := rows.Scan(
			&scan.ID,
			&uid,
			&scan.Status,
			&scan.Targets,
			&instruction,
			&scan.StartTime,
			&endTime,
			&recon,
			&vulns,
			&logs,
			&scan.InputTokens,
			&scan.OutputTokens,
			&scan.TotalCost,
			&scan.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		if uid.Valid {
			scan.UserID = uid.String
		}
		if instruction.Valid {
			scan.Instruction = instruction.String
		}
		if endTime.Valid {
			scan.EndTime = &endTime.Time
		}
		if recon.Valid {
			scan.Recon = json.RawMessage(recon.String)
		}
		if vulns.Valid {
			scan.Vulnerabilities = json.RawMessage(vulns.String)
		}
		if logs.Valid {
			scan.Logs = json.RawMessage(logs.String)
		}

		scans = append(scans, &scan)
	}

	return scans, nil
}

// =====================================================
// Report Database - Stores pentest reports and findings
// =====================================================

// ReportRecord represents a stored pentest report
type ReportRecord struct {
	ID            int64     `json:"id"`
	Target        string    `json:"target"`
	ScanDate      time.Time `json:"scan_date"`
	IterationNum  int       `json:"iteration_num"`
	FilePath      string    `json:"file_path"`
	VulnCount     int       `json:"vuln_count"`
	CredCount     int       `json:"cred_count"`
	CriticalCount int       `json:"critical_count"`
	HighCount     int       `json:"high_count"`
	MediumCount   int       `json:"medium_count"`
	LowCount      int       `json:"low_count"`
	RiskRating    string    `json:"risk_rating"`
	ReportData    string    `json:"report_data"`
	CreatedAt     time.Time `json:"created_at"`
}

// VulnerabilityRecord represents a stored vulnerability finding
type VulnerabilityRecord struct {
	ID          int64     `json:"id"`
	ReportID    int64     `json:"report_id"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Target      string    `json:"target"`
	Description string    `json:"description"`
	Details     string    `json:"details"`
	CreatedAt   time.Time `json:"created_at"`
}

// CredentialRecord represents a stored credential
type CredentialRecord struct {
	ID        int64     `json:"id"`
	ReportID  int64     `json:"report_id"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	Hash      string    `json:"hash"`
	Type      string    `json:"type"`
	Source    string    `json:"source"`
	Service   string    `json:"service"`
	CreatedAt time.Time `json:"created_at"`
}

// ReportDB manages the storage of pentest reports
type ReportDB struct {
	db     *sql.DB
	dbPath string
}

// NewReportDB creates a new report database connection
func NewReportDB(dbPath string) (*ReportDB, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	rdb := &ReportDB{db: db, dbPath: dbPath}
	if err := rdb.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return rdb, nil
}

// initSchema creates the database tables if they don't exist
func (r *ReportDB) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS reports (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target TEXT NOT NULL,
		scan_date DATETIME NOT NULL,
		iteration_num INTEGER NOT NULL,
		file_path TEXT,
		vuln_count INTEGER DEFAULT 0,
		cred_count INTEGER DEFAULT 0,
		critical_count INTEGER DEFAULT 0,
		high_count INTEGER DEFAULT 0,
		medium_count INTEGER DEFAULT 0,
		low_count INTEGER DEFAULT 0,
		risk_rating TEXT,
		report_data TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		report_id INTEGER NOT NULL,
		type TEXT NOT NULL,
		severity TEXT NOT NULL,
		target TEXT,
		description TEXT,
		details TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (report_id) REFERENCES reports(id)
	);

	CREATE TABLE IF NOT EXISTS credentials (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		report_id INTEGER NOT NULL,
		username TEXT,
		password TEXT,
		hash TEXT,
		type TEXT,
		source TEXT,
		service TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (report_id) REFERENCES reports(id)
	);

	CREATE INDEX IF NOT EXISTS idx_reports_target ON reports(target);
	CREATE INDEX IF NOT EXISTS idx_reports_scan_date ON reports(scan_date);
	CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
	CREATE INDEX IF NOT EXISTS idx_credentials_report ON credentials(report_id);
	`

	_, err := r.db.Exec(schema)
	return err
}

// Close closes the database connection
func (r *ReportDB) Close() error {
	return r.db.Close()
}

// GetNextIterationNum returns the next iteration number for reports
func (r *ReportDB) GetNextIterationNum() (int, error) {
	var maxNum sql.NullInt64
	err := r.db.QueryRow(`SELECT MAX(iteration_num) FROM reports`).Scan(&maxNum)
	if err != nil {
		return 1, err
	}
	if !maxNum.Valid {
		return 1, nil
	}
	return int(maxNum.Int64) + 1, nil
}

// SaveReport saves a new report and returns its ID
func (r *ReportDB) SaveReport(record *ReportRecord) (int64, error) {
	result, err := r.db.Exec(`
		INSERT INTO reports (
			target, scan_date, iteration_num, file_path,
			vuln_count, cred_count, critical_count, high_count,
			medium_count, low_count, risk_rating, report_data
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		record.Target, record.ScanDate, record.IterationNum, record.FilePath,
		record.VulnCount, record.CredCount, record.CriticalCount, record.HighCount,
		record.MediumCount, record.LowCount, record.RiskRating, record.ReportData,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// SaveVulnerability saves a vulnerability associated with a report
func (r *ReportDB) SaveVulnerability(vuln *VulnerabilityRecord) (int64, error) {
	result, err := r.db.Exec(`
		INSERT INTO vulnerabilities (report_id, type, severity, target, description, details)
		VALUES (?, ?, ?, ?, ?, ?)
	`, vuln.ReportID, vuln.Type, vuln.Severity, vuln.Target, vuln.Description, vuln.Details)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// SaveCredential saves a credential associated with a report
func (r *ReportDB) SaveCredential(cred *CredentialRecord) (int64, error) {
	result, err := r.db.Exec(`
		INSERT INTO credentials (report_id, username, password, hash, type, source, service)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, cred.ReportID, cred.Username, cred.Password, cred.Hash, cred.Type, cred.Source, cred.Service)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// GetReport retrieves a report by ID
func (r *ReportDB) GetReport(id int64) (*ReportRecord, error) {
	record := &ReportRecord{}
	err := r.db.QueryRow(`
		SELECT id, target, scan_date, iteration_num, file_path,
			vuln_count, cred_count, critical_count, high_count,
			medium_count, low_count, risk_rating, report_data, created_at
		FROM reports WHERE id = ?
	`, id).Scan(
		&record.ID, &record.Target, &record.ScanDate, &record.IterationNum, &record.FilePath,
		&record.VulnCount, &record.CredCount, &record.CriticalCount, &record.HighCount,
		&record.MediumCount, &record.LowCount, &record.RiskRating, &record.ReportData, &record.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return record, nil
}

// ListReports returns all reports, optionally filtered by target
func (r *ReportDB) ListReports(target string, limit int) ([]*ReportRecord, error) {
	var rows *sql.Rows
	var err error

	query := `
		SELECT id, target, scan_date, iteration_num, file_path,
			vuln_count, cred_count, critical_count, high_count,
			medium_count, low_count, risk_rating, created_at
		FROM reports
	`

	if target != "" {
		query += " WHERE target LIKE ?"
		query += " ORDER BY scan_date DESC"
		if limit > 0 {
			query += fmt.Sprintf(" LIMIT %d", limit)
		}
		rows, err = r.db.Query(query, "%"+target+"%")
	} else {
		query += " ORDER BY scan_date DESC"
		if limit > 0 {
			query += fmt.Sprintf(" LIMIT %d", limit)
		}
		rows, err = r.db.Query(query)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reports []*ReportRecord
	for rows.Next() {
		record := &ReportRecord{}
		err := rows.Scan(
			&record.ID, &record.Target, &record.ScanDate, &record.IterationNum, &record.FilePath,
			&record.VulnCount, &record.CredCount, &record.CriticalCount, &record.HighCount,
			&record.MediumCount, &record.LowCount, &record.RiskRating, &record.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		reports = append(reports, record)
	}
	return reports, nil
}

// GetVulnerabilitiesByReport returns all vulnerabilities for a report
func (r *ReportDB) GetVulnerabilitiesByReport(reportID int64) ([]*VulnerabilityRecord, error) {
	rows, err := r.db.Query(`
		SELECT id, report_id, type, severity, target, description, details, created_at
		FROM vulnerabilities WHERE report_id = ?
		ORDER BY CASE severity
			WHEN 'critical' THEN 1
			WHEN 'high' THEN 2
			WHEN 'medium' THEN 3
			WHEN 'low' THEN 4
			ELSE 5
		END
	`, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulns []*VulnerabilityRecord
	for rows.Next() {
		v := &VulnerabilityRecord{}
		err := rows.Scan(&v.ID, &v.ReportID, &v.Type, &v.Severity, &v.Target, &v.Description, &v.Details, &v.CreatedAt)
		if err != nil {
			return nil, err
		}
		vulns = append(vulns, v)
	}
	return vulns, nil
}

// GetCredentialsByReport returns all credentials for a report
func (r *ReportDB) GetCredentialsByReport(reportID int64) ([]*CredentialRecord, error) {
	rows, err := r.db.Query(`
		SELECT id, report_id, username, password, hash, type, source, service, created_at
		FROM credentials WHERE report_id = ?
	`, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []*CredentialRecord
	for rows.Next() {
		c := &CredentialRecord{}
		err := rows.Scan(&c.ID, &c.ReportID, &c.Username, &c.Password, &c.Hash, &c.Type, &c.Source, &c.Service, &c.CreatedAt)
		if err != nil {
			return nil, err
		}
		creds = append(creds, c)
	}
	return creds, nil
}

// SearchCredentials searches for credentials by username or source
func (r *ReportDB) SearchCredentials(query string) ([]*CredentialRecord, error) {
	rows, err := r.db.Query(`
		SELECT c.id, c.report_id, c.username, c.password, c.hash, c.type, c.source, c.service, c.created_at
		FROM credentials c
		WHERE c.username LIKE ? OR c.source LIKE ? OR c.service LIKE ?
		ORDER BY c.created_at DESC
	`, "%"+query+"%", "%"+query+"%", "%"+query+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []*CredentialRecord
	for rows.Next() {
		c := &CredentialRecord{}
		err := rows.Scan(&c.ID, &c.ReportID, &c.Username, &c.Password, &c.Hash, &c.Type, &c.Source, &c.Service, &c.CreatedAt)
		if err != nil {
			return nil, err
		}
		creds = append(creds, c)
	}
	return creds, nil
}

// GetStatistics returns overall statistics
func (r *ReportDB) GetStatistics() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	var totalReports int
	r.db.QueryRow("SELECT COUNT(*) FROM reports").Scan(&totalReports)
	stats["total_reports"] = totalReports

	rows, err := r.db.Query(`SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity`)
	if err == nil {
		defer rows.Close()
		vulnCounts := make(map[string]int)
		for rows.Next() {
			var severity string
			var count int
			rows.Scan(&severity, &count)
			vulnCounts[severity] = count
		}
		stats["vulnerabilities_by_severity"] = vulnCounts
	}

	var totalCreds int
	r.db.QueryRow("SELECT COUNT(*) FROM credentials").Scan(&totalCreds)
	stats["total_credentials"] = totalCreds

	var uniqueTargets int
	r.db.QueryRow("SELECT COUNT(DISTINCT target) FROM reports").Scan(&uniqueTargets)
	stats["unique_targets"] = uniqueTargets

	return stats, nil
}

// DeleteReport deletes a report and its associated data
func (r *ReportDB) DeleteReport(id int64) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}

	_, err = tx.Exec("DELETE FROM credentials WHERE report_id = ?", id)
	if err != nil {
		tx.Rollback()
		return err
	}

	_, err = tx.Exec("DELETE FROM vulnerabilities WHERE report_id = ?", id)
	if err != nil {
		tx.Rollback()
		return err
	}

	_, err = tx.Exec("DELETE FROM reports WHERE id = ?", id)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}
