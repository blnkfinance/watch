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
	"strings"
	"testing"
	"time"
)

func TestInject(t *testing.T) {
	clearTransactions(t)

	tx := Transaction{
		TransactionID: "inj-1",
		Amount:        250.5,
		Currency:      "USD",
		Source:        "src-1",
		Destination:   "dst-1",
		Description:   "test injection",
		MetaData:      map[string]interface{}{"channel": "web"},
		CreatedAt:     time.Now().UTC(),
	}

	got, err := inject(tx)
	if err != nil {
		t.Fatalf("inject: %v", err)
	}
	if got.TransactionID != "inj-1" {
		t.Errorf("unexpected transaction id: %s", got.TransactionID)
	}

	stored, err := getTransactionByID("inj-1")
	if err != nil {
		t.Fatalf("getTransactionByID: %v", err)
	}
	if stored.Amount != 250.5 || stored.Currency != "USD" || stored.Source != "src-1" {
		t.Errorf("stored transaction mismatch: %+v", stored)
	}
	if stored.MetaData["channel"] != "web" {
		t.Errorf("metadata mismatch: %+v", stored.MetaData)
	}
}

func TestInjectValidation(t *testing.T) {
	if _, err := inject(Transaction{}); err == nil || !strings.Contains(err.Error(), "transaction ID is required") {
		t.Errorf("empty transaction ID should be rejected, got %v", err)
	}
}

func TestInjectDefaultsTimestampAndMetadata(t *testing.T) {
	clearTransactions(t)

	got, err := inject(Transaction{TransactionID: "inj-defaults"})
	if err != nil {
		t.Fatalf("inject: %v", err)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt should be defaulted")
	}

	stored, err := getTransactionByID("inj-defaults")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if stored.MetaData == nil {
		t.Error("metadata should default to empty map")
	}
}

func TestGetTransactionByIDNotFound(t *testing.T) {
	clearTransactions(t)
	if _, err := getTransactionByID("nope"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not found error, got %v", err)
	}
}

func TestFetchUnprocessedTransactions(t *testing.T) {
	clearTransactions(t)

	ts := time.Now().UTC().Format("2006-01-02 15:04:05")
	insertTestTransaction(t, "un-1", 10, "USD", "s", "d", ts, "", "")                                          // no status
	insertTestTransaction(t, "un-2", 20, "USD", "s", "d", ts, "", `{"evaluation_status": "pending"}`)          // wrong status
	insertTestTransaction(t, "un-3", 30, "USD", "s", "d", ts, "", `{"evaluation_status": "completed"}`)        // done
	insertTestTransaction(t, "un-4", 40, "USD", "s", "d", ts, "", `{"evaluation_status": "completed", "x":1}`) // done

	got, err := fetchUnprocessedTransactions(10)
	if err != nil {
		t.Fatalf("fetchUnprocessedTransactions: %v", err)
	}
	ids := make(map[string]bool)
	for _, tx := range got {
		ids[tx.TransactionID] = true
	}
	if len(got) != 2 || !ids["un-1"] || !ids["un-2"] {
		t.Errorf("expected un-1 and un-2, got %+v", ids)
	}

	// Limit is respected.
	got, err = fetchUnprocessedTransactions(1)
	if err != nil {
		t.Fatalf("fetch with limit: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("expected 1 transaction with limit 1, got %d", len(got))
	}
}

func TestEvaluateTransactionAppliesRules(t *testing.T) {
	clearTransactions(t)
	clearInstructions(t)

	dsl := `{"id":10,"name":"large-txn","when":[{"field":"amount","op":"gt","value":1000}],"then":{"verdict":"review","score":0.9,"reason":"amount over 1000"}}`
	if _, err := CreateInstructionWithPrecompiledDSL(context.Background(), "large-txn", "text", "", dsl); err != nil {
		t.Fatalf("create instruction: %v", err)
	}

	tx := Transaction{
		TransactionID: "eval-1",
		Amount:        5000,
		Currency:      "USD",
		CreatedAt:     time.Now().UTC(),
	}

	got, err := evaluateTransaction(tx)
	if err != nil {
		t.Fatalf("evaluateTransaction: %v", err)
	}

	if got.MetaData["evaluation_status"] != "completed" {
		t.Errorf("evaluation_status = %v", got.MetaData["evaluation_status"])
	}
	verdicts, ok := got.MetaData["dsl_verdicts"].([]RiskVerdict)
	if !ok {
		t.Fatalf("dsl_verdicts has unexpected type %T", got.MetaData["dsl_verdicts"])
	}
	if len(verdicts) != 1 || verdicts[0].Verdict != "review" || verdicts[0].Score != 0.9 {
		t.Errorf("unexpected verdicts: %+v", verdicts)
	}

	// A transaction below the threshold gets no verdicts.
	small := Transaction{TransactionID: "eval-2", Amount: 5, CreatedAt: time.Now().UTC()}
	got, err = evaluateTransaction(small)
	if err != nil {
		t.Fatalf("evaluateTransaction small: %v", err)
	}
	if verdicts, _ := got.MetaData["dsl_verdicts"].([]RiskVerdict); len(verdicts) != 0 {
		t.Errorf("expected no verdicts, got %+v", verdicts)
	}
}

func TestProcessTransactionRiskEvaluation(t *testing.T) {
	clearTransactions(t)
	clearInstructions(t)
	t.Setenv("ALERT_WEBHOOK_ENABLED", "false")

	dsl := `{"id":11,"name":"flag-all","when":[{"field":"amount","op":"gt","value":100}],"then":{"verdict":"block","score":1.0,"reason":"flagged"}}`
	if _, err := CreateInstructionWithPrecompiledDSL(context.Background(), "flag-all", "text", "", dsl); err != nil {
		t.Fatalf("create instruction: %v", err)
	}

	ts := time.Now().UTC()
	tx := Transaction{
		TransactionID: "proc-1",
		Amount:        500,
		Currency:      "USD",
		CreatedAt:     ts,
	}
	if _, err := inject(tx); err != nil {
		t.Fatalf("inject: %v", err)
	}

	if err := processTransactionRiskEvaluation(tx); err != nil {
		t.Fatalf("processTransactionRiskEvaluation: %v", err)
	}

	stored, err := getTransactionByID("proc-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if stored.MetaData["evaluation_status"] != "completed" {
		t.Errorf("evaluation_status = %v", stored.MetaData["evaluation_status"])
	}
	if _, ok := stored.MetaData["consolidated_risk_assessment"]; !ok {
		t.Errorf("expected consolidated_risk_assessment in metadata: %+v", stored.MetaData)
	}
}

func TestProcessTransactionBatch(t *testing.T) {
	clearTransactions(t)
	clearInstructions(t)
	t.Setenv("ALERT_WEBHOOK_ENABLED", "false")

	ts := time.Now().UTC().Format("2006-01-02 15:04:05")
	insertTestTransaction(t, "batch-1", 10, "USD", "s", "d", ts, "", "")
	insertTestTransaction(t, "batch-2", 20, "USD", "s", "d", ts, "", "")

	processTransactionBatch()

	for _, id := range []string{"batch-1", "batch-2"} {
		stored, err := getTransactionByID(id)
		if err != nil {
			t.Fatalf("get %s: %v", id, err)
		}
		if stored.MetaData["evaluation_status"] != "completed" {
			t.Errorf("%s not processed: %+v", id, stored.MetaData)
		}
	}

	// A second run with nothing left to process is a no-op.
	processTransactionBatch()
}

func TestCopyTransactionsRequiresDBURL(t *testing.T) {
	t.Setenv("DB_URL", "")
	if err := CopyTransactionsFromPostgreSQL(10); err == nil || !strings.Contains(err.Error(), "DB_URL") {
		t.Errorf("expected DB_URL error, got %v", err)
	}
	if err := CopyAllTransactionsFromPostgreSQL(); err == nil || !strings.Contains(err.Error(), "DB_URL") {
		t.Errorf("expected DB_URL error, got %v", err)
	}
}
