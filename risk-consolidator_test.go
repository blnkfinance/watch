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
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestRiskConsolidatorName(t *testing.T) {
	s := &RiskConsolidatorSkill{}
	if s.Name() != "RiskConsolidatorSkill" {
		t.Errorf("Name = %q", s.Name())
	}
}

func TestExecuteNoVerdicts(t *testing.T) {
	t.Setenv("ALERT_WEBHOOK_ENABLED", "false")
	s := &RiskConsolidatorSkill{}

	tx := Transaction{TransactionID: "rc-1"}
	if err := s.Execute(tx); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// MetaData was nil; Execute initializes it internally but the caller's
	// copy is unaffected (Transaction passed by value). Test with metadata set.

	tx = Transaction{TransactionID: "rc-2", MetaData: map[string]interface{}{}}
	if err := s.Execute(tx); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	assessment, ok := tx.MetaData["consolidated_risk_assessment"].(ConsolidatedRiskAssessment)
	if !ok {
		t.Fatalf("missing assessment: %+v", tx.MetaData)
	}
	if assessment.FinalVerdict != "Indeterminate" || assessment.SourceCount != 0 || assessment.FinalRiskScore != 0 {
		t.Errorf("unexpected assessment: %+v", assessment)
	}
}

func TestExecuteConsolidatesVerdicts(t *testing.T) {
	t.Setenv("ALERT_WEBHOOK_ENABLED", "false")
	s := &RiskConsolidatorSkill{}

	tx := Transaction{
		TransactionID: "rc-3",
		MetaData: map[string]interface{}{
			"dsl_verdicts": []RiskVerdict{
				{RuleID: 1, Verdict: "review", Score: 0.6, Reason: "reason-a"},
				{RuleID: 2, Verdict: "block", Score: 1.0, Reason: "reason-b"},
			},
		},
	}
	if err := s.Execute(tx); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	assessment := tx.MetaData["consolidated_risk_assessment"].(ConsolidatedRiskAssessment)
	if assessment.FinalRiskScore != 0.8 {
		t.Errorf("score = %v, want 0.8 (average)", assessment.FinalRiskScore)
	}
	if assessment.FinalVerdict != "block" {
		t.Errorf("verdict = %q, want block (score >= 0.7)", assessment.FinalVerdict)
	}
	if assessment.SourceCount != 2 {
		t.Errorf("source count = %d", assessment.SourceCount)
	}
	if assessment.FinalReason != "reason-a; reason-b" {
		t.Errorf("reason = %q", assessment.FinalReason)
	}
}

func TestExecuteScoreClamping(t *testing.T) {
	t.Setenv("ALERT_WEBHOOK_ENABLED", "false")
	s := &RiskConsolidatorSkill{}

	tx := Transaction{
		TransactionID: "rc-clamp-high",
		MetaData: map[string]interface{}{
			"dsl_verdicts": []RiskVerdict{{Score: 5.0, Reason: "over"}},
		},
	}
	if err := s.Execute(tx); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if a := tx.MetaData["consolidated_risk_assessment"].(ConsolidatedRiskAssessment); a.FinalRiskScore != 1.0 {
		t.Errorf("score should clamp to 1.0, got %v", a.FinalRiskScore)
	}

	tx = Transaction{
		TransactionID: "rc-clamp-low",
		MetaData: map[string]interface{}{
			"dsl_verdicts": []RiskVerdict{{Score: -2.0, Reason: "under"}},
		},
	}
	if err := s.Execute(tx); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	a := tx.MetaData["consolidated_risk_assessment"].(ConsolidatedRiskAssessment)
	if a.FinalRiskScore != 0.0 {
		t.Errorf("score should clamp to 0.0, got %v", a.FinalRiskScore)
	}
	if a.FinalVerdict != "review" {
		t.Errorf("verdict = %q, want review (score < 0.7)", a.FinalVerdict)
	}
}

func TestExecuteIgnoresWrongVerdictType(t *testing.T) {
	t.Setenv("ALERT_WEBHOOK_ENABLED", "false")
	s := &RiskConsolidatorSkill{}

	// dsl_verdicts of the wrong type (e.g. after a JSON round-trip) is skipped.
	tx := Transaction{
		TransactionID: "rc-wrong-type",
		MetaData: map[string]interface{}{
			"dsl_verdicts": []interface{}{map[string]interface{}{"score": 0.9}},
		},
	}
	if err := s.Execute(tx); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	a := tx.MetaData["consolidated_risk_assessment"].(ConsolidatedRiskAssessment)
	if a.FinalVerdict != "Indeterminate" {
		t.Errorf("wrong-typed verdicts should be ignored, got %+v", a)
	}
}

func TestFlagAnomalyToCloud(t *testing.T) {
	var received atomic.Int32
	var lastBody []byte

	okServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		lastBody, _ = io.ReadAll(r.Body)
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("missing content type")
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("missing auth header, got %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"received": true}`))
	}))
	defer okServer.Close()

	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer failServer.Close()

	s := &RiskConsolidatorSkill{}
	assessment := ConsolidatedRiskAssessment{FinalRiskScore: 0.9, FinalVerdict: "block", FinalReason: "test", SourceCount: 1}
	tx := Transaction{
		TransactionID: "cloud-1",
		Amount:        100,
		MetaData:      map[string]interface{}{"dsl_verdicts": []RiskVerdict{{Score: 0.9}}},
	}

	t.Run("primary succeeds", func(t *testing.T) {
		t.Setenv("ALERT_WEBHOOK_URL", okServer.URL)
		t.Setenv("ALERT_WEBHOOK_API_KEY", "test-key")
		t.Setenv("ALERT_WEBHOOK_SECONDARY_URL", "")
		t.Setenv("ALERT_WEBHOOK_BACKUP_URL", "")

		if err := s.flagAnomalyToCloud(tx, assessment); err != nil {
			t.Fatalf("flagAnomalyToCloud: %v", err)
		}
		var req CloudAnomalyRequest
		if err := json.Unmarshal(lastBody, &req); err != nil {
			t.Fatalf("bad request body: %v", err)
		}
		if req.TransactionID != "cloud-1" || req.RiskLevel != "high" || req.Verdict != "block" {
			t.Errorf("unexpected request: %+v", req)
		}
	})

	t.Run("falls back to secondary", func(t *testing.T) {
		before := received.Load()
		t.Setenv("ALERT_WEBHOOK_URL", failServer.URL)
		t.Setenv("ALERT_WEBHOOK_API_KEY", "test-key")
		t.Setenv("ALERT_WEBHOOK_SECONDARY_URL", okServer.URL)
		t.Setenv("ALERT_WEBHOOK_BACKUP_URL", "")

		if err := s.flagAnomalyToCloud(tx, assessment); err != nil {
			t.Fatalf("fallback should succeed: %v", err)
		}
		if received.Load() != before+1 {
			t.Errorf("secondary webhook was not hit")
		}
	})

	t.Run("all fail", func(t *testing.T) {
		t.Setenv("ALERT_WEBHOOK_URL", failServer.URL)
		t.Setenv("ALERT_WEBHOOK_SECONDARY_URL", "")
		t.Setenv("ALERT_WEBHOOK_BACKUP_URL", "")

		if err := s.flagAnomalyToCloud(tx, assessment); err == nil {
			t.Error("expected error when all webhooks fail")
		}
	})

	t.Run("no webhooks configured is a no-op", func(t *testing.T) {
		t.Setenv("ALERT_WEBHOOK_URL", "")
		t.Setenv("ALERT_WEBHOOK_SECONDARY_URL", "")
		t.Setenv("ALERT_WEBHOOK_BACKUP_URL", "")

		if err := s.flagAnomalyToCloud(tx, assessment); err != nil {
			t.Errorf("no webhooks should be a no-op, got %v", err)
		}
	})
}

func TestFlagAnomalyRiskLevels(t *testing.T) {
	var gotLevel string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req CloudAnomalyRequest
		json.NewDecoder(r.Body).Decode(&req)
		gotLevel = req.RiskLevel
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	t.Setenv("ALERT_WEBHOOK_URL", server.URL)
	t.Setenv("ALERT_WEBHOOK_SECONDARY_URL", "")
	t.Setenv("ALERT_WEBHOOK_BACKUP_URL", "")

	s := &RiskConsolidatorSkill{}
	tx := Transaction{TransactionID: "levels"}

	tests := []struct {
		score float64
		want  string
	}{
		{0.9, "high"},
		{0.65, "medium"},
		{0.4, "low"},
		{0.1, "very_low"},
	}
	for _, tt := range tests {
		if err := s.flagAnomalyToCloud(tx, ConsolidatedRiskAssessment{FinalRiskScore: tt.score}); err != nil {
			t.Fatalf("flag score %v: %v", tt.score, err)
		}
		if gotLevel != tt.want {
			t.Errorf("score %v -> level %q, want %q", tt.score, gotLevel, tt.want)
		}
	}
}

func TestFlagAnomalyViaWebSocket(t *testing.T) {
	saved := globalTunnel
	defer func() { globalTunnel = saved }()

	s := &RiskConsolidatorSkill{}
	assessment := ConsolidatedRiskAssessment{FinalRiskScore: 0.85, FinalVerdict: "block", FinalReason: "ws test"}
	tx := Transaction{TransactionID: "ws-1", MetaData: map[string]interface{}{}}

	globalTunnel = &mockGlobalTunnel{}
	if err := s.flagAnomalyViaWebSocket(tx, assessment); err != nil {
		t.Fatalf("flagAnomalyViaWebSocket: %v", err)
	}
	if tx.MetaData["websocket_anomaly_flagged"] != true {
		t.Errorf("metadata not marked: %+v", tx.MetaData)
	}
	if tx.MetaData["websocket_anomaly_risk_level"] != "high" {
		t.Errorf("risk level = %v, want high", tx.MetaData["websocket_anomaly_risk_level"])
	}

	globalTunnel = nil
	if err := s.flagAnomalyViaWebSocket(tx, assessment); err == nil {
		t.Error("nil tunnel should error")
	}
}

func TestExecuteFallsBackToWebhookWhenTunnelFails(t *testing.T) {
	saved := globalTunnel
	defer func() { globalTunnel = saved }()
	globalTunnel = nil // WebSocket path fails

	var hit atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	t.Setenv("ALERT_WEBHOOK_URL", server.URL)
	t.Setenv("ALERT_WEBHOOK_SECONDARY_URL", "")
	t.Setenv("ALERT_WEBHOOK_BACKUP_URL", "")
	t.Setenv("ALERT_WEBHOOK_ENABLED", "")

	s := &RiskConsolidatorSkill{}
	tx := Transaction{
		TransactionID: "fallback-1",
		MetaData: map[string]interface{}{
			"dsl_verdicts": []RiskVerdict{{Verdict: "block", Score: 0.9, Reason: "r"}},
		},
	}
	if err := s.Execute(tx); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !hit.Load() {
		t.Error("webhook fallback was not invoked")
	}
}

func TestExecuteThresholdParsing(t *testing.T) {
	saved := globalTunnel
	defer func() { globalTunnel = saved }()
	globalTunnel = &mockGlobalTunnel{}

	s := &RiskConsolidatorSkill{}

	// Invalid threshold falls back to the default without failing.
	t.Setenv("ALERT_WEBHOOK_RISK_THRESHOLD", "not-a-number")
	tx := Transaction{
		TransactionID: "thresh-1",
		MetaData: map[string]interface{}{
			"dsl_verdicts": []RiskVerdict{{Verdict: "review", Score: 0.6, Reason: "r"}},
		},
	}
	if err := s.Execute(tx); err != nil {
		t.Fatalf("Execute with bad threshold: %v", err)
	}

	t.Setenv("ALERT_WEBHOOK_RISK_THRESHOLD", "0.9")
	if err := s.Execute(tx); err != nil {
		t.Fatalf("Execute with valid threshold: %v", err)
	}
}
