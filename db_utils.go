/*
Copyright 2024 Blnk Finance Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package watch

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/duckdb/duckdb-go/v2"
	"github.com/rs/zerolog/log"
)

const instructionDBFilename = "instructions.duckdb"

const dbFilename = "blnk.duckdb"

var instructionDB *sql.DB

// watchDBDir is the absolute on-disk directory holding the watch DuckDB files.
// It is resolved once at startup so DuckDB's data/WAL/temp paths never depend on
// the process working directory — which git operations briefly change.
var watchDBDir = resolveWatchDBDir()

var duckDBTempDir = filepath.Join(watchDBDir, "duckdb_temp")

func resolveWatchDBDir() string {
	if abs, err := filepath.Abs("blnk_watch_db"); err == nil {
		return abs
	}
	return "blnk_watch_db"
}

const (
	duckDBAccessMode          = "READ_WRITE"
	duckDBThreads             = 1
	duckDBMemoryLimit         = "2GiB"
	duckDBCheckpointThreshold = "64MiB"
	duckDBConnMaxLifetime     = 10 * time.Minute
)

var (
	transactionsDB *sql.DB
	dbMutex        sync.RWMutex
)

var ErrTransactionNotFound = errors.New("transaction not found")

type Instruction struct {
	ID          int64          `json:"id"`
	Name        string         `json:"name"`
	Text        string         `json:"text"`
	Description string         `json:"description"`
	DSLJSON     sql.NullString `json:"dsl_json,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

func getInstructionDBPath() (string, error) {
	if err := os.MkdirAll(watchDBDir, 0755); err != nil {
		log.Error().Err(err).Str("dir", watchDBDir).Msg("Error creating instruction data directory")
		return "", err
	}
	return filepath.Join(watchDBDir, instructionDBFilename), nil
}

func ensureInstructionSchema(db *sql.DB) error {
	const sequenceName = "instructions_id_seq"

	seqQuery := fmt.Sprintf(`CREATE SEQUENCE IF NOT EXISTS %s START 1;`, sequenceName)
	_, err := db.Exec(seqQuery)
	if err != nil {
		log.Error().Err(err).Str("sequenceName", sequenceName).Msg("Failed to create sequence")
		return fmt.Errorf("failed to create sequence %s: %w", sequenceName, err)
	}

	tableQuery := fmt.Sprintf(`
	CREATE TABLE IF NOT EXISTS instructions (
		id BIGINT PRIMARY KEY DEFAULT nextval('%s'),
		name TEXT NOT NULL UNIQUE,
		text TEXT NOT NULL,
		description TEXT,
		dsl_json JSON NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`, sequenceName)
	_, err = db.Exec(tableQuery)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create instructions table with explicit sequence")
		return fmt.Errorf("failed to create instructions table: %w", err)
	}

	return nil
}

func InitInstructionDB() error {
	dbPath, err := getInstructionDBPath()
	if err != nil {
		return fmt.Errorf("failed to get instruction database path: %w", err)
	}
	db, err := sql.Open("duckdb", dbPath)
	if err != nil {
		log.Error().Err(err).Str("db_path", dbPath).Msg("Error opening database for instructions")
		return err
	}

	if err = db.Ping(); err != nil {
		log.Error().Err(err).Str("db_path", dbPath).Msg("Failed to ping instruction database")
		db.Close()
		return err
	}

	if err := ensureInstructionSchema(db); err != nil {
		db.Close()
		return err
	}
	instructionDB = db
	return nil
}

func CloseInstructionDB() {
	if instructionDB != nil {
		err := instructionDB.Close()
		if err != nil {
			log.Error().Err(err).Msg("Error closing instruction database")
		} else {
			log.Info().Msg("Instruction database connection closed.")
		}
	}
}

// createInstructionRecord creates a new instruction without a dsl_json field. Hence, this
// instruction is not an "active" rule and there is no need to invalidate global active
// rules cache when it inserts an instruction in the DB.
func createInstructionRecord(db *sql.DB, name, text, description string) (int64, error) {
	query := `
		INSERT INTO instructions (name, text, description)
		VALUES (?, ?, ?)
		RETURNING id;
	`
	var id int64
	err := db.QueryRow(query, name, text, description).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func getDBPath() (string, error) {
	if err := os.MkdirAll(watchDBDir, 0755); err != nil {
		log.Error().Err(err).Str("dir", watchDBDir).Msg("Error creating data directory")
		return "", err
	}
	return filepath.Join(watchDBDir, dbFilename), nil
}

func ensureSchema(db *sql.DB) error {
	tableQuery := `
	CREATE TABLE IF NOT EXISTS transactions (
		transaction_id VARCHAR NOT NULL,
		amount DOUBLE,
		currency VARCHAR,
		source VARCHAR,
		destination VARCHAR,
		timestamp TIMESTAMP,
		description VARCHAR,
		metadata JSON,
		PRIMARY KEY (transaction_id)
	);
	`
	_, err := db.Exec(tableQuery)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create transactions table")
		return fmt.Errorf("failed to create transactions table: %w", err)
	}
	watermarkQuery := `
	CREATE TABLE IF NOT EXISTS sync_watermark (
		id INTEGER PRIMARY KEY DEFAULT 1,
		-- Transactions watermark
		last_sync_timestamp TIMESTAMP,
		last_transaction_id VARCHAR,
		total_synced_count BIGINT DEFAULT 0,
		-- General sync info
		last_sync_completed_at TIMESTAMP,
		sync_status VARCHAR DEFAULT 'idle',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		CHECK (id = 1)
	);
	`
	_, err = db.Exec(watermarkQuery)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create sync_watermark table")
		return fmt.Errorf("failed to create sync_watermark table: %w", err)
	}

	initWatermarkQuery := `
	INSERT OR IGNORE INTO sync_watermark (
		id, 
		last_sync_timestamp, 
		sync_status
	) 
	VALUES (1, ?, 'idle');
	`
	_, err = db.Exec(initWatermarkQuery, defaultInitialSyncTimestamp())
	if err != nil {
		log.Error().Err(err).Msg("Failed to initialize sync watermark")
		return fmt.Errorf("failed to initialize sync watermark: %w", err)
	}

	sourceIndexQuery := `CREATE INDEX IF NOT EXISTS idx_transactions_source ON transactions (source);`
	_, err = db.Exec(sourceIndexQuery)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create index on source")
		return fmt.Errorf("failed to create index on source: %w", err)
	}

	destIndexQuery := `CREATE INDEX IF NOT EXISTS idx_transactions_destination ON transactions (destination);`
	_, err = db.Exec(destIndexQuery)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create index on destination")
		return fmt.Errorf("failed to create index on destination: %w", err)
	}

	timestampIndexQuery := `CREATE INDEX IF NOT EXISTS idx_transactions_timestamp ON transactions (timestamp);`
	_, err = db.Exec(timestampIndexQuery)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create index on timestamp")
		return fmt.Errorf("failed to create index on timestamp: %w", err)
	}
	return nil
}

func InitTransactionsDB() error {
	dbMutex.RLock()
	if transactionsDB != nil {
		dbMutex.RUnlock()
		return nil
	}
	dbMutex.RUnlock()

	dbPath, err := getDBPath()
	if err != nil {
		return fmt.Errorf("failed to get transactions database path: %w", err)
	}

	db, err := openTransactionsDBConnection(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open transactions database: %w", err)
	}

	if err := ensureSchema(db); err != nil {
		db.Close()
		return err
	}

	dbMutex.Lock()
	transactionsDB = db
	dbMutex.Unlock()

	go periodicCheckpoint()
	return nil
}

func CloseTransactionsDB() {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	if transactionsDB != nil {
		if _, err := transactionsDB.Exec("CHECKPOINT"); err != nil {
			log.Error().Err(err).Msg("Failed to checkpoint database before closing")
		}

		err := transactionsDB.Close()
		if err != nil {
			log.Error().Err(err).Msg("Error closing transactions database")
		} else {
			log.Info().Msg("Transactions database connection closed.")
		}
		transactionsDB = nil
	}
}

func getDB() (*sql.DB, error) {
	dbMutex.RLock()
	defer dbMutex.RUnlock()

	if transactionsDB == nil {
		return nil, fmt.Errorf("transactions database not initialized")
	}
	return transactionsDB, nil
}

func GetDB() (*sql.DB, error) {
	return getDB()
}

func getSyncDB() (*sql.DB, error) {
	return getDB()
}

func GetSyncDB() (*sql.DB, error) {
	return getSyncDB()
}

func openTransactionsDBConnection(dbPath string) (*sql.DB, error) {
	connStr := fmt.Sprintf("%s", dbPath)
	db, err := sql.Open("duckdb", connStr)
	if err != nil {
		log.Error().Err(err).Str("db_path", dbPath).Msg("Error opening database for transactions")
		return nil, err
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(duckDBConnMaxLifetime)

	if err = db.Ping(); err != nil {
		log.Error().Err(err).Str("db_path", dbPath).Msg("Failed to ping transactions database")
		db.Close()
		return nil, err
	}

	if err := os.MkdirAll(duckDBTempDir, 0755); err != nil {
		log.Error().Err(err).Msg("Failed to create DuckDB temp directory")
		db.Close()
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	pragmas := []string{
		fmt.Sprintf("SET memory_limit='%s'", duckDBMemoryLimit),
		fmt.Sprintf("SET temp_directory='%s'", duckDBTempDir),
		fmt.Sprintf("SET threads=%d", duckDBThreads),
		fmt.Sprintf("SET checkpoint_threshold='%s'", duckDBCheckpointThreshold),
		"SET enable_progress_bar=false",
		"SET preserve_insertion_order=false",
		"SET null_order='nulls_first'",
	}

	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			log.Error().Err(err).Str("pragma", pragma).Msg("Failed to set DuckDB pragma")
			db.Close()
			return nil, fmt.Errorf("failed to set pragma %s: %w", pragma, err)
		}
	}

	return db, nil
}

func updateTransactionMetadataInDB(txID string, metadata map[string]interface{}) error {

	db, err := getDB()
	if err != nil {
		log.Error().Str("tx_id", txID).Msg("Transactions database not initialized")
		return err
	}

	maxRetries := 3
	for attempt := 1; attempt <= maxRetries; attempt++ {
		err = updateTransactionMetadataAttempt(db, txID, metadata)
		if err == nil {
			return nil
		}

		if isRecoverableError(err) && attempt < maxRetries {
			log.Warn().
				Err(err).
				Str("tx_id", txID).
				Int("attempt", attempt).
				Int("max_retries", maxRetries).
				Msg("Retrying metadata update after recoverable error")

			time.Sleep(time.Duration(attempt) * 100 * time.Millisecond)
			continue
		}

		return err
	}

	return err
}

func isRecoverableError(err error) bool {
	errStr := err.Error()
	return contains(errStr, "Could not read enough bytes") ||
		contains(errStr, "IO Error") ||
		contains(errStr, "database is locked") ||
		contains(errStr, "connection reset")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			containsHelper(s, substr)))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func updateTransactionMetadataAttempt(db *sql.DB, txID string, metadata map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tx, err := db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelDefault,
		ReadOnly:  false,
	})
	if err != nil {
		log.Error().Err(err).Str("tx_id", txID).Msg("Failed to begin transaction")
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				log.Error().Err(rollbackErr).Str("tx_id", txID).Msg("Failed to rollback transaction")
			}
		}
	}()

	var exists bool
	existsQuery := "SELECT EXISTS(SELECT 1 FROM transactions WHERE transaction_id = ?) as exists"
	err = tx.QueryRowContext(ctx, existsQuery, txID).Scan(&exists)
	if err != nil {
		log.Error().
			Err(err).
			Str("tx_id", txID).
			Str("query", existsQuery).
			Msg("Failed to check if transaction exists")
		return fmt.Errorf("failed to check if transaction exists: %w", err)
	}

	if !exists {
		return ErrTransactionNotFound
	}

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		log.Error().Err(err).Str("tx_id", txID).Msg("Failed to marshal metadata")
		return fmt.Errorf("failed to serialize metadata for update: %w", err)
	}

	metadataStr := string(metadataJSON)

	var testParse map[string]interface{}
	if err := json.Unmarshal([]byte(metadataStr), &testParse); err != nil {
		log.Error().Err(err).Str("tx_id", txID).Msg("Generated invalid JSON")
		return fmt.Errorf("generated invalid JSON: %w", err)
	}

	stmt, err := tx.PrepareContext(ctx, `UPDATE transactions SET metadata = ? WHERE transaction_id = ?`)
	if err != nil {
		log.Error().Err(err).Str("tx_id", txID).Msg("Failed to prepare update statement")
		return fmt.Errorf("failed to prepare update statement: %w", err)
	}
	defer stmt.Close()

	result, err := stmt.ExecContext(ctx, metadataStr, txID)
	if err != nil {
		log.Error().Err(err).Str("tx_id", txID).Msg("Failed to execute update statement")
		return fmt.Errorf("failed to execute update statement: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Error().Err(err).Str("tx_id", txID).Msg("Failed to get rows affected")
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		log.Error().Str("tx_id", txID).Msg("No rows were updated")
		return fmt.Errorf("no rows were updated for transaction %s", txID)
	}

	if err = tx.Commit(); err != nil {
		log.Error().Err(err).Str("tx_id", txID).Msg("Failed to commit transaction")
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func periodicCheckpoint() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		if db, err := getDB(); err == nil {
			if _, err := db.Exec("CHECKPOINT"); err != nil {
				log.Error().Err(err).Msg("Failed to perform periodic checkpoint")
			} else {
				log.Debug().Msg("Periodic checkpoint completed successfully")
			}
		}
	}
}
