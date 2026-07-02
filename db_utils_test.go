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
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGetDBPaths(t *testing.T) {
	p, err := getDBPath()
	if err != nil {
		t.Fatalf("getDBPath: %v", err)
	}
	if filepath.Base(p) != dbFilename {
		t.Errorf("getDBPath = %q, want basename %q", p, dbFilename)
	}

	ip, err := getInstructionDBPath()
	if err != nil {
		t.Fatalf("getInstructionDBPath: %v", err)
	}
	if filepath.Base(ip) != instructionDBFilename {
		t.Errorf("getInstructionDBPath = %q, want basename %q", ip, instructionDBFilename)
	}
}

func TestGetDBAccessors(t *testing.T) {
	db, err := getDB()
	if err != nil || db == nil {
		t.Fatalf("getDB = (%v, %v)", db, err)
	}
	if db2, err := GetDB(); err != nil || db2 != db {
		t.Errorf("GetDB should return same handle")
	}
	if db3, err := getSyncDB(); err != nil || db3 != db {
		t.Errorf("getSyncDB should return same handle")
	}
	if db4, err := GetSyncDB(); err != nil || db4 != db {
		t.Errorf("GetSyncDB should return same handle")
	}
}

func TestInitTransactionsDBIdempotent(t *testing.T) {
	// DB is already initialized by TestMain; a second call must be a no-op.
	if err := InitTransactionsDB(); err != nil {
		t.Fatalf("second InitTransactionsDB should succeed: %v", err)
	}
}

func TestEnsureSchemaIdempotent(t *testing.T) {
	db, err := getDB()
	if err != nil {
		t.Fatalf("getDB: %v", err)
	}
	if err := ensureSchema(db); err != nil {
		t.Fatalf("ensureSchema should be idempotent: %v", err)
	}
	if err := ensureInstructionSchema(instructionDB); err != nil {
		t.Fatalf("ensureInstructionSchema should be idempotent: %v", err)
	}
}

func TestUpdateTransactionMetadataInDB(t *testing.T) {
	clearTransactions(t)

	ts := time.Now().UTC().Format("2006-01-02 15:04:05")
	insertTestTransaction(t, "meta-1", 50, "USD", "src", "dst", ts, "", `{"initial": true}`)

	newMeta := map[string]interface{}{
		"evaluation_status": "completed",
		"score":             0.7,
	}
	if err := updateTransactionMetadataInDB("meta-1", newMeta); err != nil {
		t.Fatalf("updateTransactionMetadataInDB: %v", err)
	}

	got, err := getTransactionByID("meta-1")
	if err != nil {
		t.Fatalf("getTransactionByID: %v", err)
	}
	if got.MetaData["evaluation_status"] != "completed" {
		t.Errorf("metadata not updated: %+v", got.MetaData)
	}
	if _, stillThere := got.MetaData["initial"]; stillThere {
		t.Errorf("metadata should be fully replaced, got %+v", got.MetaData)
	}

	// Missing transaction returns the sentinel error.
	err = updateTransactionMetadataInDB("does-not-exist", newMeta)
	if !errors.Is(err, ErrTransactionNotFound) {
		t.Errorf("expected ErrTransactionNotFound, got %v", err)
	}

	// Unmarshalable metadata errors out.
	badMeta := map[string]interface{}{"fn": func() {}}
	if err := updateTransactionMetadataInDB("meta-1", badMeta); err == nil {
		t.Error("unmarshalable metadata should error")
	}
}

func TestIsRecoverableError(t *testing.T) {
	recoverable := []string{
		"Could not read enough bytes",
		"IO Error: something",
		"database is locked",
		"unexpected connection reset by peer",
	}
	for _, msg := range recoverable {
		if !isRecoverableError(errors.New(msg)) {
			t.Errorf("expected %q to be recoverable", msg)
		}
	}
	if isRecoverableError(errors.New("syntax error")) {
		t.Error("syntax error should not be recoverable")
	}
}

// contains is a hand-rolled substring check; verify it agrees with the
// standard library across edge cases.
func TestContainsMatchesStdlib(t *testing.T) {
	cases := []struct{ s, substr string }{
		{"", ""},
		{"a", ""},
		{"", "a"},
		{"abc", "abc"},
		{"abc", "ab"},
		{"abc", "bc"},
		{"abc", "b"},
		{"abc", "abcd"},
		{"database is locked somewhere", "database is locked"},
		{"prefix IO Error", "IO Error"},
		{"xxIO Errorxx", "IO Error"},
		{"aaa", "aa"},
		{"ababab", "bab"},
	}
	for _, c := range cases {
		got := contains(c.s, c.substr)
		want := strings.Contains(c.s, c.substr)
		if got != want {
			t.Errorf("contains(%q, %q) = %v, stdlib says %v", c.s, c.substr, got, want)
		}
	}
}

func TestCreateInstructionRecord(t *testing.T) {
	clearInstructions(t)

	id, err := createInstructionRecord(instructionDB, "rec-test", "script text", "a description")
	if err != nil {
		t.Fatalf("createInstructionRecord: %v", err)
	}
	if id <= 0 {
		t.Errorf("expected positive id, got %d", id)
	}

	// Duplicate name violates the UNIQUE constraint.
	if _, err := createInstructionRecord(instructionDB, "rec-test", "other", "other"); err == nil {
		t.Error("duplicate instruction name should error")
	}
}

func TestUpdateTransactionMetadataRoundTripJSON(t *testing.T) {
	clearTransactions(t)
	ts := time.Now().UTC().Format("2006-01-02 15:04:05")
	insertTestTransaction(t, "meta-rt", 10, "USD", "s", "d", ts, "", "")

	meta := map[string]interface{}{
		"nested": map[string]interface{}{"key": "value"},
		"list":   []interface{}{1.0, 2.0},
	}
	if err := updateTransactionMetadataInDB("meta-rt", meta); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err := getTransactionByID("meta-rt")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	b, _ := json.Marshal(got.MetaData["nested"])
	if string(b) != `{"key":"value"}` {
		t.Errorf("nested metadata mismatch: %s", b)
	}
}
