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
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/rs/zerolog/log"
)

type Transaction struct {
	ID                 int64                  `json:"-"`
	PreciseAmount      *big.Int               `json:"precise_amount,omitempty"`
	Amount             float64                `json:"amount"`
	AmountString       string                 `json:"amount_string,omitempty"`
	Rate               float64                `json:"rate"`
	Precision          float64                `json:"precision"`
	OverdraftLimit     float64                `json:"overdraft_limit"`
	TransactionID      string                 `json:"transaction_id"`
	ParentTransaction  string                 `json:"parent_transaction"`
	Source             string                 `json:"source,omitempty"`
	Destination        string                 `json:"destination,omitempty"`
	Reference          string                 `json:"reference"`
	Currency           string                 `json:"currency"`
	Description        string                 `json:"description,omitempty"`
	Status             string                 `json:"status"`
	Hash               string                 `json:"hash"`
	AllowOverdraft     bool                   `json:"allow_overdraft"`
	Inflight           bool                   `json:"inflight"`
	SkipBalanceUpdate  bool                   `json:"-"`
	SkipQueue          bool                   `json:"skip_queue"`
	Atomic             bool                   `json:"atomic"`
	CreatedAt          time.Time              `json:"created_at"`
	EffectiveDate      *time.Time             `json:"effective_date,omitempty"`
	ScheduledFor       time.Time              `json:"scheduled_for,omitempty"`
	InflightExpiryDate time.Time              `json:"inflight_expiry_date,omitempty"`
	MetaData           map[string]interface{} `json:"meta_data,omitempty"`
}

func inject(t Transaction) (Transaction, error) {
	db, err := getDB()
	if err != nil {
		return t, fmt.Errorf("failed to get database connection: %w", err)
	}

	txID := t.TransactionID
	if t.TransactionID == "" {
		return t, fmt.Errorf("transaction ID is required")
	}

	metadata := t.MetaData
	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return t, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	timestamp := t.CreatedAt
	if timestamp.IsZero() {
		timestamp = time.Now()
		t.CreatedAt = timestamp
	}

	query := `
		INSERT OR REPLACE INTO transactions (transaction_id, amount, currency, source, destination, timestamp, description, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = db.Exec(query,
		txID,
		t.Amount,
		t.Currency,
		t.Source,
		t.Destination,
		timestamp,
		t.Description,
		string(metadataJSON),
	)

	if err != nil {
		return t, fmt.Errorf("failed to insert transaction into database: %w", err)
	}

	log.Info().
		Str("transaction_id", txID).
		Float64("amount", t.Amount).
		Str("currency", t.Currency).
		Str("source", t.Source).
		Str("destination", t.Destination).
		Msg("Transaction successfully injected into database")

	return t, nil
}

func evaluateTransaction(t Transaction) (Transaction, error) {
	if t.MetaData == nil {
		t.MetaData = make(map[string]interface{})
	}

	db, err := getDB()
	if err != nil {
		return t, fmt.Errorf("failed to get database connection: %w", err)
	}

	activeRules, err := getActiveRules()
	if err != nil {
		fmt.Printf("failed to get active rules: %+v\n", err)
		return t, fmt.Errorf("failed to get active rules: %w", err)
	}

	transactionMap := map[string]any{
		"transaction_id": t.TransactionID,
		"amount":         t.Amount,
		"currency":       t.Currency,
		"source":         t.Source,
		"destination":    t.Destination,
		"description":    t.Description,
		"meta_data":      t.MetaData,
		"created_at":     t.CreatedAt,
	}

	aggCtx, err := BuildAggContext(context.Background(), db, transactionMap, activeRules)
	if err != nil {
		return t, fmt.Errorf("failed to build aggregate context: %w", err)
	}
	verdicts, err := EvaluateRules(transactionMap, activeRules, aggCtx)
	if err != nil {
		return t, fmt.Errorf("failed to evaluate rules: %w", err)
	}

	log.Info().
		Str("transaction_id", t.TransactionID).
		Msg("Blnk Watch evaluation complete.")

	t.MetaData["dsl_verdicts"] = verdicts
	t.MetaData["risk_evaluation_timestamp"] = time.Now()
	t.MetaData["evaluation_status"] = "completed"

	return t, nil
}

func fetchUnprocessedTransactions(limit int) ([]Transaction, error) {
	db, err := getDB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database connection: %w", err)
	}

	query := `
		SELECT transaction_id, amount, currency, source, destination, timestamp, description, metadata
		FROM transactions 
		WHERE JSON_EXTRACT(metadata, '$.evaluation_status') != '"completed"'
		   OR JSON_EXTRACT(metadata, '$.evaluation_status') IS NULL
		ORDER BY timestamp ASC
		LIMIT ?
	`

	rows, err := db.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query unprocessed transactions: %w", err)
	}
	defer rows.Close()

	var transactions []Transaction
	for rows.Next() {
		var t Transaction
		var metadataRaw interface{}
		var timestamp time.Time

		err := rows.Scan(
			&t.TransactionID,
			&t.Amount,
			&t.Currency,
			&t.Source,
			&t.Destination,
			&timestamp,
			&t.Description,
			&metadataRaw,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan transaction row: %w", err)
		}

		t.CreatedAt = timestamp

		if metadataRaw != nil {
			switch v := metadataRaw.(type) {
			case string:
				if v != "" {
					err = json.Unmarshal([]byte(v), &t.MetaData)
					if err != nil {
						log.Warn().
							Str("transaction_id", t.TransactionID).
							Err(err).
							Msg("Failed to parse transaction metadata from string, initializing empty")
						t.MetaData = make(map[string]interface{})
					}
				} else {
					t.MetaData = make(map[string]interface{})
				}
			case map[string]interface{}:
				t.MetaData = v
			default:
				jsonBytes, err := json.Marshal(v)
				if err != nil {
					log.Warn().
						Str("transaction_id", t.TransactionID).
						Err(err).
						Msg("Failed to marshal metadata, initializing empty")
					t.MetaData = make(map[string]interface{})
				} else {
					err = json.Unmarshal(jsonBytes, &t.MetaData)
					if err != nil {
						log.Warn().
							Str("transaction_id", t.TransactionID).
							Err(err).
							Msg("Failed to unmarshal metadata, initializing empty")
						t.MetaData = make(map[string]interface{})
					}
				}
			}
		} else {
			t.MetaData = make(map[string]interface{})
		}

		transactions = append(transactions, t)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating transaction rows: %w", err)
	}

	return transactions, nil
}

func getTransactionByID(transactionID string) (Transaction, error) {
	db, err := getDB()
	if err != nil {
		return Transaction{}, fmt.Errorf("failed to get database connection: %w", err)
	}

	query := `
		SELECT transaction_id, amount, currency, source, destination, timestamp, description, metadata
		FROM transactions 
		WHERE transaction_id = ?
	`

	var t Transaction
	var metadataRaw interface{}
	var timestamp time.Time

	err = db.QueryRow(query, transactionID).Scan(
		&t.TransactionID,
		&t.Amount,
		&t.Currency,
		&t.Source,
		&t.Destination,
		&timestamp,
		&t.Description,
		&metadataRaw,
	)
	if err != nil {
		return Transaction{}, fmt.Errorf("transaction not found: %w", err)
	}

	t.CreatedAt = timestamp

	if metadataRaw != nil {
		switch v := metadataRaw.(type) {
		case string:
			if v != "" {
				err = json.Unmarshal([]byte(v), &t.MetaData)
				if err != nil {
					log.Warn().
						Str("transaction_id", t.TransactionID).
						Err(err).
						Msg("Failed to parse transaction metadata from string, initializing empty")
					t.MetaData = make(map[string]interface{})
				}
			} else {
				t.MetaData = make(map[string]interface{})
			}
		case map[string]interface{}:
			t.MetaData = v
		default:
			jsonBytes, err := json.Marshal(v)
			if err != nil {
				log.Warn().
					Str("transaction_id", t.TransactionID).
					Err(err).
					Msg("Failed to marshal metadata, initializing empty")
				t.MetaData = make(map[string]interface{})
			} else {
				err = json.Unmarshal(jsonBytes, &t.MetaData)
				if err != nil {
					log.Warn().
						Str("transaction_id", t.TransactionID).
						Err(err).
						Msg("Failed to unmarshal metadata, initializing empty")
					t.MetaData = make(map[string]interface{})
				}
			}
		}
	} else {
		t.MetaData = make(map[string]interface{})
	}

	return t, nil
}

func startRiskEvaluationWorker() {
	log.Info().Msg("Starting risk evaluation worker")

	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for range ticker.C {
			processTransactionBatch()
		}
	}()
}

func processTransactionBatch() {
	batchSize := 10
	transactions, err := fetchUnprocessedTransactions(batchSize)
	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch unprocessed transactions")
		return
	}

	if len(transactions) == 0 {
		return
	}

	for _, transaction := range transactions {
		err := processTransactionRiskEvaluation(transaction)
		if err != nil {
			log.Error().
				Err(err).
				Str("transaction_id", transaction.TransactionID).
				Msg("Failed to process transaction risk evaluation")
			continue
		}
	}

}

// processTransactionRiskEvaluation processes a single transaction for risk evaluation
func processTransactionRiskEvaluation(t Transaction) error {

	// Run risk evaluation
	evaluatedTransaction, err := evaluateTransaction(t)
	if err != nil {
		return fmt.Errorf("failed to evaluate transaction: %w", err)
	}

	consolidator := &RiskConsolidatorSkill{}
	err = consolidator.Execute(evaluatedTransaction)
	if err != nil {
		log.Error().
			Err(err).
			Str("transaction_id", t.TransactionID).
			Msg("Failed to consolidate risk assessment, continuing with basic evaluation")
	}

	// Update transaction metadata in database
	err = updateTransactionMetadataInDB(evaluatedTransaction.TransactionID, evaluatedTransaction.MetaData)
	if err != nil {
		return fmt.Errorf("failed to update transaction metadata: %w", err)
	}

	return nil
}

func CopyTransactionsFromPostgreSQL(limit int) error {
	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		return fmt.Errorf("DB_URL environment variable is required")
	}

	// Get DuckDB connection
	db, err := getSyncDB()
	if err != nil {
		return fmt.Errorf("failed to get DuckDB connection: %w", err)
	}

	log.Info().
		Int("limit", limit).
		Msg("Starting PostgreSQL to DuckDB copy using native extension")

	_, err = db.Exec("INSTALL postgres; LOAD postgres;")
	if err != nil {
		return fmt.Errorf("failed to install/load PostgreSQL extension: %w", err)
	}

	attachQuery := fmt.Sprintf("ATTACH '%s' AS postgres_db (TYPE postgres);", dbURL)
	_, err = db.Exec(attachQuery)
	if err != nil {
		return fmt.Errorf("failed to attach PostgreSQL database: %w", err)
	}
	defer func() {
		if _, err := db.Exec("DETACH postgres_db;"); err != nil {
			log.Error().Err(err).Msg("Failed to detach PostgreSQL database")
		}
	}()

	copyQuery := fmt.Sprintf(`
		INSERT OR REPLACE INTO transactions (transaction_id, amount, currency, source, destination, timestamp, description, metadata)
		SELECT 
			transaction_id as transaction_id,
			COALESCE(amount, 0) as amount,
			COALESCE(currency, '') as currency,
			COALESCE(source, '') as source,
			COALESCE(destination, '') as destination,
			COALESCE(created_at, NOW()) as timestamp,
			COALESCE(description, '') as description,
			COALESCE(meta_data, '{}') as metadata
		FROM postgres_db.blnk.transactions 
		WHERE status IS NOT NULL AND status != 'QUEUED'
		ORDER BY created_at DESC
		LIMIT %d;
	`, limit)

	result, err := db.Exec(copyQuery)
	if err != nil {
		return fmt.Errorf("failed to copy transactions from PostgreSQL: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Warn().Err(err).Msg("Could not determine number of rows copied")
		rowsAffected = 0
	}

	log.Info().
		Int64("rows_copied", rowsAffected).
		Int("limit", limit).
		Msg("Successfully copied transactions from PostgreSQL to DuckDB using native extension")

	return nil
}

func CopyAllTransactionsFromPostgreSQL() error {
	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		return fmt.Errorf("DB_URL environment variable is required")
	}

	// Get DuckDB connection
	db, err := getSyncDB()
	if err != nil {
		return fmt.Errorf("failed to get DuckDB connection: %w", err)
	}

	log.Info().Msg("Starting full PostgreSQL to DuckDB copy using COPY FROM DATABASE")

	_, err = db.Exec("INSTALL postgres; LOAD postgres;")
	if err != nil {
		return fmt.Errorf("failed to install/load PostgreSQL extension: %w", err)
	}

	attachQuery := fmt.Sprintf("ATTACH '%s' AS postgres_source (TYPE postgres);", dbURL)
	_, err = db.Exec(attachQuery)
	if err != nil {
		return fmt.Errorf("failed to attach PostgreSQL database: %w", err)
	}
	defer func() {
		if _, err := db.Exec("DETACH postgres_source;"); err != nil {
			log.Error().Err(err).Msg("Failed to detach PostgreSQL database")
		}
	}()

	createViewQuery := `
		CREATE OR REPLACE TEMPORARY VIEW filtered_transactions AS
		SELECT 
			transaction_id as transaction_id,
			COALESCE(amount, 0) as amount,
			COALESCE(currency, '') as currency,
			COALESCE(source, '') as source,
			COALESCE(destination, '') as destination,
			COALESCE(created_at, NOW()) as timestamp,
			COALESCE(description, '') as description,
			COALESCE(meta_data, '{}') as metadata
		FROM postgres_source.blnk.transactions 
		WHERE status IS NOT NULL AND status != 'QUEUED';
	`

	_, err = db.Exec(createViewQuery)
	if err != nil {
		return fmt.Errorf("failed to create filtered transactions view: %w", err)
	}

	copyQuery := `
		INSERT OR REPLACE INTO transactions 
		SELECT * FROM filtered_transactions;
	`

	result, err := db.Exec(copyQuery)
	if err != nil {
		return fmt.Errorf("failed to copy all transactions from PostgreSQL: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Warn().Err(err).Msg("Could not determine number of rows copied")
		rowsAffected = 0
	}

	_, err = db.Exec("DROP VIEW IF EXISTS filtered_transactions;")
	if err != nil {
		log.Warn().Err(err).Msg("Failed to clean up temporary view")
	}

	log.Info().
		Int64("total_rows_copied", rowsAffected).
		Msg("Successfully completed full copy of transactions from PostgreSQL to DuckDB")

	return nil
}
