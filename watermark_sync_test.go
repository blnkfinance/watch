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
	"database/sql"
	"strings"
	"testing"
	"time"
)

func TestDefaultSyncConfig(t *testing.T) {
	cfg := DefaultSyncConfig()
	if cfg.SyncInterval != 10*time.Second || cfg.BatchSize != 1000 || cfg.MaxRetries != 3 || !cfg.EnableSync {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
	if cfg.TransactionStartTime.IsZero() {
		t.Error("TransactionStartTime should be set")
	}
}

func TestNewWatermarkSyncer(t *testing.T) {
	ws := NewWatermarkSyncer(nil)
	if ws.config == nil {
		t.Fatal("nil config should get defaults")
	}

	custom := &SyncConfig{SyncInterval: time.Minute, BatchSize: 10, EnableSync: false}
	ws = NewWatermarkSyncer(custom)
	if ws.config != custom {
		t.Error("custom config not retained")
	}
}

func TestWatermarkSyncerStartStop(t *testing.T) {
	// Disabled sync starts as a no-op.
	ws := NewWatermarkSyncer(&SyncConfig{EnableSync: false})
	if err := ws.Start(); err != nil {
		t.Fatalf("disabled Start: %v", err)
	}
	if ws.running {
		t.Error("disabled syncer should not be running")
	}
	ws.Stop() // Stop on a non-running syncer is a no-op.
}

func TestParseSyncStartTime(t *testing.T) {
	tests := []struct {
		in   string
		want time.Time
	}{
		{"2026-01-02T15:04:05Z", time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)},
		{"2026-01-02 15:04:05", time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)},
		{"2026-01-02", time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)},
	}
	for _, tt := range tests {
		got, err := parseSyncStartTime(tt.in)
		if err != nil {
			t.Errorf("parseSyncStartTime(%q) error: %v", tt.in, err)
			continue
		}
		if !got.Equal(tt.want) {
			t.Errorf("parseSyncStartTime(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}

	if _, err := parseSyncStartTime("bogus"); err == nil {
		t.Error("invalid time should error")
	}
}

func TestResolveDefaultTransactionStartTime(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

	t.Run("default lookback", func(t *testing.T) {
		t.Setenv(syncStartTimeEnv, "")
		t.Setenv(syncLookbackWindowEnv, "")
		got := resolveDefaultTransactionStartTime(now)
		want := now.Add(-defaultSyncLookbackWindow)
		if !got.Equal(want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("explicit start time", func(t *testing.T) {
		t.Setenv(syncStartTimeEnv, "2026-01-01")
		got := resolveDefaultTransactionStartTime(now)
		if !got.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
			t.Errorf("got %v", got)
		}
	})

	t.Run("invalid start time falls back", func(t *testing.T) {
		t.Setenv(syncStartTimeEnv, "garbage")
		t.Setenv(syncLookbackWindowEnv, "")
		got := resolveDefaultTransactionStartTime(now)
		if !got.Equal(now.Add(-defaultSyncLookbackWindow)) {
			t.Errorf("got %v", got)
		}
	})

	t.Run("custom lookback", func(t *testing.T) {
		t.Setenv(syncStartTimeEnv, "")
		t.Setenv(syncLookbackWindowEnv, "2h")
		got := resolveDefaultTransactionStartTime(now)
		if !got.Equal(now.Add(-2 * time.Hour)) {
			t.Errorf("got %v", got)
		}
	})

	t.Run("invalid lookback uses default", func(t *testing.T) {
		t.Setenv(syncStartTimeEnv, "")
		t.Setenv(syncLookbackWindowEnv, "-5h")
		got := resolveDefaultTransactionStartTime(now)
		if !got.Equal(now.Add(-defaultSyncLookbackWindow)) {
			t.Errorf("got %v", got)
		}
	})
}

func TestNormalizeInitialWatermark(t *testing.T) {
	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	ws := NewWatermarkSyncer(&SyncConfig{TransactionStartTime: start})

	// Untouched watermark at the epoch gets bumped to the configured start.
	w := &SyncWatermark{LastSyncTimestamp: initialSyncEpoch}
	ws.normalizeInitialWatermark(w)
	if !w.LastSyncTimestamp.Equal(start) {
		t.Errorf("epoch watermark should normalize to start time, got %v", w.LastSyncTimestamp)
	}

	// Watermark with progress is left alone.
	progressed := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	w = &SyncWatermark{LastSyncTimestamp: progressed, TotalSyncedCount: 5}
	ws.normalizeInitialWatermark(w)
	if !w.LastSyncTimestamp.Equal(progressed) {
		t.Errorf("progressed watermark should be untouched, got %v", w.LastSyncTimestamp)
	}

	// Epoch watermark with a transaction id is left alone.
	w = &SyncWatermark{LastSyncTimestamp: initialSyncEpoch, LastTransactionID: "tx-1"}
	ws.normalizeInitialWatermark(w)
	if !w.LastSyncTimestamp.Equal(initialSyncEpoch) {
		t.Errorf("watermark with txn id should be untouched, got %v", w.LastSyncTimestamp)
	}
}

func TestBuildTimestampWhereClause(t *testing.T) {
	ws := NewWatermarkSyncer(nil)
	ts := time.Date(2026, 6, 1, 10, 30, 0, 0, time.UTC)

	clause := ws.buildTimestampWhereClause(&SyncWatermark{LastSyncTimestamp: ts})
	if clause != "AND pg_txn.created_at > '2026-06-01 10:30:00'" {
		t.Errorf("clause = %q", clause)
	}

	clause = ws.buildTimestampWhereClause(&SyncWatermark{LastSyncTimestamp: ts, LastTransactionID: "tx-9"})
	if !strings.Contains(clause, "pg_txn.transaction_id > 'tx-9'") || !strings.Contains(clause, "created_at = '2026-06-01 10:30:00'") {
		t.Errorf("tie-break clause = %q", clause)
	}
}

func TestBuildQueries(t *testing.T) {
	ws := NewWatermarkSyncer(&SyncConfig{BatchSize: 42, TransactionStartTime: time.Now()})
	w := &SyncWatermark{LastSyncTimestamp: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)}

	copyQuery := ws.buildCopyQuery(w)
	if !strings.Contains(copyQuery, "LIMIT 42") || !strings.Contains(copyQuery, "INSERT OR REPLACE INTO transactions") {
		t.Errorf("copy query missing pieces:\n%s", copyQuery)
	}
	if !strings.Contains(copyQuery, "status != 'QUEUED'") {
		t.Errorf("copy query should exclude queued transactions")
	}

	boundaryQuery := ws.buildBatchBoundaryQuery(w)
	if !strings.Contains(boundaryQuery, "LIMIT 42") || !strings.Contains(boundaryQuery, "MAX(created_at)") {
		t.Errorf("boundary query missing pieces:\n%s", boundaryQuery)
	}
}

func TestCalculateNewWatermark(t *testing.T) {
	ws := NewWatermarkSyncer(nil)
	prev := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	batchMax := time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC)
	w := &SyncWatermark{LastSyncTimestamp: prev}

	// No rows copied keeps the previous watermark.
	if got := ws.calculateNewWatermark(w, sql.NullTime{}, 0); !got.Equal(prev) {
		t.Errorf("no rows: got %v, want %v", got, prev)
	}
	// Rows copied with a valid max timestamp advances to it.
	if got := ws.calculateNewWatermark(w, sql.NullTime{Time: batchMax, Valid: true}, 5); !got.Equal(batchMax) {
		t.Errorf("valid max: got %v, want %v", got, batchMax)
	}
	// Rows copied but invalid max falls back to roughly now.
	got := ws.calculateNewWatermark(w, sql.NullTime{}, 5)
	if time.Since(got) > time.Minute {
		t.Errorf("fallback should be ~now, got %v", got)
	}
}

func TestShouldLogIdleCycle(t *testing.T) {
	ws := NewWatermarkSyncer(nil)
	now := time.Now()

	if !ws.shouldLogIdleCycle(now) {
		t.Error("first idle cycle should log")
	}
	if ws.shouldLogIdleCycle(now.Add(10 * time.Second)) {
		t.Error("idle cycle within interval should not log")
	}
	if !ws.shouldLogIdleCycle(now.Add(syncIdleLogInterval + time.Second)) {
		t.Error("idle cycle after interval should log")
	}
}

func TestWatermarkDBRoundTrip(t *testing.T) {
	db, err := GetSyncDB()
	if err != nil {
		t.Fatalf("GetSyncDB: %v", err)
	}

	start := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	ws := NewWatermarkSyncer(&SyncConfig{TransactionStartTime: start, BatchSize: 100})

	// Reset to a known state first.
	if err := ws.ResetWatermark(); err != nil {
		t.Fatalf("ResetWatermark: %v", err)
	}

	w, err := ws.getWatermark(db)
	if err != nil {
		t.Fatalf("getWatermark: %v", err)
	}
	if !w.LastSyncTimestamp.Equal(start) || w.TotalSyncedCount != 0 || w.SyncStatus != "idle" {
		t.Errorf("unexpected watermark after reset: %+v", w)
	}

	// Update the watermark as a completed sync would.
	newMark := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	result := &SyncResult{TransactionWatermark: newMark, LastTransactionID: "tx-42", TransactionsSynced: 7, HasBatch: true}
	if err := ws.updateWatermarkFull(db, result); err != nil {
		t.Fatalf("updateWatermarkFull: %v", err)
	}

	w, err = ws.getWatermark(db)
	if err != nil {
		t.Fatalf("getWatermark after update: %v", err)
	}
	if !w.LastSyncTimestamp.Equal(newMark) || w.LastTransactionID != "tx-42" || w.TotalSyncedCount != 7 {
		t.Errorf("watermark not updated: %+v", w)
	}

	// Zero watermark in a result is floored to the configured start time.
	if err := ws.updateWatermarkFull(db, &SyncResult{TransactionWatermark: time.Time{}}); err != nil {
		t.Fatalf("updateWatermarkFull zero: %v", err)
	}
	w, _ = ws.getWatermark(db)
	if !w.LastSyncTimestamp.Equal(start) {
		t.Errorf("zero watermark should floor to start, got %v", w.LastSyncTimestamp)
	}

	// Status updates round-trip.
	if err := ws.updateSyncStatus(db, "running"); err != nil {
		t.Fatalf("updateSyncStatus: %v", err)
	}
	status, err := ws.GetSyncStatus()
	if err != nil {
		t.Fatalf("GetSyncStatus: %v", err)
	}
	if status.SyncStatus != "running" {
		t.Errorf("sync status = %q, want running", status.SyncStatus)
	}

	// Restore idle for other tests.
	if err := ws.updateSyncStatus(db, "idle"); err != nil {
		t.Fatalf("restore status: %v", err)
	}
}

func TestSyncTransactionsIncrementalRequiresDBURL(t *testing.T) {
	t.Setenv("DB_URL", "")
	ws := NewWatermarkSyncer(&SyncConfig{MaxRetries: 1, TransactionStartTime: time.Now()})
	if err := ws.syncTransactionsIncremental(); err == nil || !strings.Contains(err.Error(), "DB_URL") {
		t.Errorf("expected DB_URL error, got %v", err)
	}

	// performSync surfaces the same failure after retries.
	if err := ws.performSync(); err == nil || !strings.Contains(err.Error(), "sync failed after 1 attempts") {
		t.Errorf("expected retry-exhausted error, got %v", err)
	}
}

func TestAttachPostgresDBInvalidURL(t *testing.T) {
	db, err := GetSyncDB()
	if err != nil {
		t.Fatalf("GetSyncDB: %v", err)
	}
	if err := attachPostgresDB(db, "://bad-url"); err == nil {
		t.Error("invalid URL should error")
	}
}

func TestDefaultInitialSyncTimestamp(t *testing.T) {
	t.Setenv(syncStartTimeEnv, "2026-03-01")
	got := defaultInitialSyncTimestamp()
	if got != "2026-03-01 00:00:00" {
		t.Errorf("defaultInitialSyncTimestamp = %q", got)
	}
}
