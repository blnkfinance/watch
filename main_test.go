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
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestMain redirects the package-level DuckDB directories to a temp dir and
// initializes both databases once, so DB-backed code paths can be exercised
// without polluting the repository working tree.
func TestMain(m *testing.M) {
	tempDir, err := os.MkdirTemp("", "watch-test-db-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp db dir: %v\n", err)
		os.Exit(1)
	}

	watchDBDir = tempDir
	duckDBTempDir = filepath.Join(tempDir, "duckdb_temp")

	if err := InitTransactionsDB(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to init transactions db: %v\n", err)
		os.Exit(1)
	}
	if err := InitInstructionDB(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to init instruction db: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()

	CloseTransactionsDB()
	CloseInstructionDB()
	os.RemoveAll(tempDir)
	os.Exit(code)
}

// clearTransactions removes all rows from the transactions table so a test
// starts from a known-empty state.
func clearTransactions(t *testing.T) {
	t.Helper()
	db, err := getDB()
	if err != nil {
		t.Fatalf("getDB: %v", err)
	}
	if _, err := db.Exec("DELETE FROM transactions"); err != nil {
		t.Fatalf("failed to clear transactions: %v", err)
	}
}

// clearInstructions removes all rows from the instructions table.
func clearInstructions(t *testing.T) {
	t.Helper()
	if instructionDB == nil {
		t.Fatal("instruction db not initialized")
	}
	if _, err := instructionDB.Exec("DELETE FROM instructions"); err != nil {
		t.Fatalf("failed to clear instructions: %v", err)
	}
}

// insertTestTransaction inserts a transaction row directly.
func insertTestTransaction(t *testing.T, txID string, amount float64, currency, source, destination, timestamp, description, metadataJSON string) {
	t.Helper()
	db, err := getDB()
	if err != nil {
		t.Fatalf("getDB: %v", err)
	}
	if metadataJSON == "" {
		metadataJSON = "{}"
	}
	_, err = db.Exec(`
		INSERT OR REPLACE INTO transactions (transaction_id, amount, currency, source, destination, timestamp, description, metadata)
		VALUES (?, ?, ?, ?, ?, ?::TIMESTAMP, ?, ?)`,
		txID, amount, currency, source, destination, timestamp, description, metadataJSON)
	if err != nil {
		t.Fatalf("failed to insert test transaction %s: %v", txID, err)
	}
}
