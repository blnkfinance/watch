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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type ConsolidatedRiskAssessment struct {
	FinalRiskScore float64 `json:"final_risk_score"`
	FinalVerdict   string  `json:"final_verdict"`
	FinalReason    string  `json:"final_reason"`
	SourceCount    int     `json:"source_count"`
}

type RiskConsolidatorSkill struct {
}

type CloudAnomalyRequest struct {
	TransactionID  string                 `json:"transaction_id"`
	Description    string                 `json:"description"`
	RiskLevel      string                 `json:"risk_level"`
	RiskScore      float64                `json:"risk_score"`
	Verdict        string                 `json:"verdict"`
	SourceCount    int                    `json:"source_count"`
	EvaluationData map[string]interface{} `json:"evaluation_data,omitempty"`
}

type CloudAnomalyResponse map[string]interface{}

func (s *RiskConsolidatorSkill) Name() string {
	return "RiskConsolidatorSkill"
}

func (s *RiskConsolidatorSkill) flagAnomalyViaWebSocket(t Transaction, assessment ConsolidatedRiskAssessment) error {
	description := assessment.FinalReason
	if description == "" {
		description = "Risk assessment flagged transaction"
	}

	// Map risk score to risk level
	riskLevel := "medium"
	if assessment.FinalRiskScore >= 0.8 {
		riskLevel = "high"
	} else if assessment.FinalRiskScore >= 0.6 {
		riskLevel = "medium"
	} else if assessment.FinalRiskScore >= 0.3 {
		riskLevel = "low"
	} else {
		riskLevel = "very_low"
	}

	additionalData := make(map[string]interface{})
	if t.MetaData != nil {
		additionalData["original_metadata"] = t.MetaData
	}
	additionalData["transaction_amount"] = t.Amount
	additionalData["transaction_reference"] = t.Reference
	anomaly := AnomalyMessage{
		Type:           "anomaly",
		TransactionID:  t.TransactionID,
		Description:    description,
		RiskLevel:      riskLevel,
		RiskScore:      assessment.FinalRiskScore,
		Verdict:        assessment.FinalVerdict,
		Reason:         assessment.FinalReason,
		SourceCount:    assessment.SourceCount,
		Timestamp:      time.Now().Format(time.RFC3339),
		AdditionalData: additionalData,
	}

	if err := SendAnomalyToTunnel(anomaly); err != nil {
		return fmt.Errorf("failed to send anomaly via WebSocket: %w", err)
	}

	if t.MetaData == nil {
		t.MetaData = make(map[string]interface{})
	}
	t.MetaData["websocket_anomaly_flagged"] = true
	t.MetaData["websocket_anomaly_timestamp"] = time.Now()
	t.MetaData["websocket_anomaly_description"] = description
	t.MetaData["websocket_anomaly_risk_level"] = riskLevel

	return nil
}

func (s *RiskConsolidatorSkill) flagAnomalyToCloud(t Transaction, assessment ConsolidatedRiskAssessment) error {
	baseURLs := []string{}

	if primaryURL := os.Getenv("ALERT_WEBHOOK_URL"); primaryURL != "" {
		baseURLs = append(baseURLs, primaryURL)
	}

	if secondaryURL := os.Getenv("ALERT_WEBHOOK_SECONDARY_URL"); secondaryURL != "" {
		baseURLs = append(baseURLs, secondaryURL)
	}

	if backupURL := os.Getenv("ALERT_WEBHOOK_BACKUP_URL"); backupURL != "" {
		baseURLs = append(baseURLs, backupURL)
	}

	if len(baseURLs) == 0 {
		log.Printf("No webhooks configured for anomaly flagging. Skipping notification.")
		return nil
	}

	description := assessment.FinalReason
	if description == "" {
		description = "Risk assessment flagged transaction"
	}

	// Map risk score to risk level
	riskLevel := "medium"
	if assessment.FinalRiskScore >= 0.8 {
		riskLevel = "high"
	} else if assessment.FinalRiskScore >= 0.6 {
		riskLevel = "medium"
	} else if assessment.FinalRiskScore >= 0.3 {
		riskLevel = "low"
	} else {
		riskLevel = "very_low"
	}

	evaluationData := make(map[string]interface{})
	evaluationData["final_risk_score"] = assessment.FinalRiskScore
	evaluationData["final_verdict"] = assessment.FinalVerdict
	evaluationData["final_reason"] = assessment.FinalReason
	evaluationData["source_count"] = assessment.SourceCount
	if t.MetaData != nil {
		if dslVerdicts, ok := t.MetaData["dsl_verdicts"]; ok {
			evaluationData["dsl_verdicts"] = dslVerdicts
		}
	}
	evaluationData["transaction_amount"] = t.Amount
	evaluationData["transaction_reference"] = t.Reference

	request := CloudAnomalyRequest{
		TransactionID:  t.TransactionID,
		Description:    description,
		RiskLevel:      riskLevel,
		RiskScore:      assessment.FinalRiskScore,
		Verdict:        assessment.FinalVerdict,
		SourceCount:    assessment.SourceCount,
		EvaluationData: evaluationData,
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal anomaly request: %w", err)
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	var lastError error
	for i, baseURL := range baseURLs {

		log.Printf("Attempting to flag anomaly to webhook %d/%d: %s", i+1, len(baseURLs), baseURL)

		req, err := http.NewRequest("POST", baseURL, bytes.NewBuffer(jsonData))
		if err != nil {
			lastError = fmt.Errorf("failed to create request for URL %s: %w", baseURL, err)
			log.Printf("Error creating request for %s: %v", baseURL, err)
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "BlnkWatch-RiskConsolidator/1.0")

		if apiKey := os.Getenv("ALERT_WEBHOOK_API_KEY"); apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+apiKey)
		}

		resp, err := client.Do(req)
		if err != nil {
			lastError = fmt.Errorf("failed to send request to %s: %w", baseURL, err)
			log.Printf("Error sending request to %s: %v", baseURL, err)
			continue
		}

		statusCode := resp.StatusCode

		// Read and close body immediately to avoid resource leaks in loop
		var bodyBytes []byte
		if resp.Body != nil {
			bodyBytes, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
		}

		if statusCode >= 200 && statusCode < 300 {
			log.Printf("Successfully flagged anomaly to webhook %s. Status: %d", baseURL, statusCode)

			if t.MetaData == nil {
				t.MetaData = make(map[string]interface{})
			}
			t.MetaData["cloud_anomaly_flagged"] = true
			t.MetaData["cloud_anomaly_url"] = baseURL
			t.MetaData["cloud_anomaly_timestamp"] = time.Now()
			t.MetaData["cloud_anomaly_description"] = request.Description
			t.MetaData["cloud_anomaly_risk_level"] = request.RiskLevel

			// Parse response if available
			if len(bodyBytes) > 0 {
				var response CloudAnomalyResponse
				if err := json.Unmarshal(bodyBytes, &response); err == nil {
					t.MetaData["cloud_anomaly_response"] = response
				}
			}

			return nil
		}

		errMsg := fmt.Sprintf("status=%d", statusCode)
		if len(bodyBytes) > 0 {
			errMsg = fmt.Sprintf("status=%d, body=%s", statusCode, string(bodyBytes))
		}
		lastError = fmt.Errorf("webhook %s returned error: %s", baseURL, errMsg)
		log.Printf("Webhook %s returned error: %s", baseURL, errMsg)
	}

	return fmt.Errorf("failed to flag anomaly to any webhook. Last error: %w", lastError)
}

func (s *RiskConsolidatorSkill) Execute(t Transaction) error {
	if t.MetaData == nil {
		t.MetaData = make(map[string]interface{})
	}

	var allReasons []string
	var totalScore float64
	var scoreCount int

	if dslVerdictsVal, ok := t.MetaData["dsl_verdicts"]; ok {
		if dslVerdictsMap, ok := dslVerdictsVal.([]RiskVerdict); ok {
			for _, verdictMap := range dslVerdictsMap {
				score := verdictMap.Score
				reason := verdictMap.Reason

				totalScore += score
				scoreCount++
				allReasons = append(allReasons, reason)
			}
		} else {
			log.Printf("Warning: 'dsl_verdicts' key found in metadata for tx %d, but type is %T, not []map[string]any. Skipping.", t.ID, dslVerdictsVal)
		}
	}

	if scoreCount == 0 {

		t.MetaData["consolidated_risk_assessment"] = ConsolidatedRiskAssessment{
			FinalRiskScore: 0.0,
			FinalVerdict:   "Indeterminate",
			FinalReason:    "No risk information found to consolidate.",
			SourceCount:    0,
		}
		return nil
	}

	finalRiskScore := totalScore / float64(scoreCount)
	if finalRiskScore < 0 {
		finalRiskScore = 0
	}
	if finalRiskScore > 1 {
		finalRiskScore = 1
	}

	finalVerdict := "review"
	if finalRiskScore >= 0.7 {
		finalVerdict = "block"
	}

	assessment := ConsolidatedRiskAssessment{
		FinalRiskScore: finalRiskScore,
		FinalVerdict:   finalVerdict,
		FinalReason:    strings.Join(allReasons, "; "),
		SourceCount:    scoreCount,
	}

	t.MetaData["consolidated_risk_assessment"] = assessment

	shouldFlagToCloud := false

	riskThreshold := 0.5
	if thresholdStr := os.Getenv("ALERT_WEBHOOK_RISK_THRESHOLD"); thresholdStr != "" {
		if threshold, err := fmt.Sscanf(thresholdStr, "%f", &riskThreshold); err == nil && threshold == 1 {
		} else {
			log.Printf("Warning: Invalid ALERT_WEBHOOK_RISK_THRESHOLD value '%s', using default 0.5", thresholdStr)
		}
	}

	if assessment.FinalRiskScore >= riskThreshold {
		shouldFlagToCloud = true
	}

	if assessment.FinalVerdict == "block" || assessment.FinalVerdict == "review" {
		shouldFlagToCloud = true
	}

	if cloudFlaggingEnabled := os.Getenv("ALERT_WEBHOOK_ENABLED"); cloudFlaggingEnabled == "false" {
		shouldFlagToCloud = false
		log.Printf("Alert webhook is disabled via ALERT_WEBHOOK_ENABLED=false")
	}

	if shouldFlagToCloud {
		websocketErr := s.flagAnomalyViaWebSocket(t, assessment)
		if websocketErr == nil {
			log.Printf("Successfully flagged anomaly for transaction %s", t.TransactionID)
		} else {
			log.Printf("WebSocket anomaly flagging failed for transaction %s: %v", t.TransactionID, websocketErr)

			if cloudErr := s.flagAnomalyToCloud(t, assessment); cloudErr != nil {
				log.Printf("Warning: Both WebSocket and webhook alert failed for transaction %s. WebSocket: %v, Webhook: %v",
					t.TransactionID, websocketErr, cloudErr)

				t.MetaData["websocket_anomaly_error"] = websocketErr.Error()
				t.MetaData["websocket_anomaly_error_timestamp"] = time.Now()
				t.MetaData["cloud_anomaly_error"] = cloudErr.Error()
				t.MetaData["cloud_anomaly_error_timestamp"] = time.Now()
			}
		}
	} else {
		log.Printf("Anomaly for transaction %s does not meet flagging criteria (Score: %.2f, Verdict: %s)",
			t.TransactionID, assessment.FinalRiskScore, assessment.FinalVerdict)
	}

	return nil
}
