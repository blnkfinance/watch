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
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	zlog "github.com/rs/zerolog/log"
)

func handleInject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var t Transaction
	err := json.NewDecoder(r.Body).Decode(&t)
	if err != nil {
		zlog.Error().Err(err).Msg("Error decoding request body")
		http.Error(w, fmt.Sprintf("Error decoding request body: %v", err), http.StatusBadRequest)
		return
	}

	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now()
	}
	if t.TransactionID == "" {
		t.TransactionID = uuid.New().String()
	}

	log := zlog.With().Str("transaction_id", t.TransactionID).Logger()
	log.Info().Msg("Received inject request")

	t, err = inject(t)
	if err != nil {
		log.Error().Err(err).Msg("Error processing transaction")
		http.Error(w, fmt.Sprintf("Error processing transaction: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"transaction_id": t.TransactionID,
		"message":        "Call GET /transactions/{id} to fetch the processed transaction or set ALERT_WEBHOOK_URL to get webhooks when the transaction is flagged.",
	})
}

func handleBlnkWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	log := zlog.With().Str("webhook_event", "blnkWebhook").Logger()
	var payload struct {
		Event string                 `json:"event"`
		Data  map[string]interface{} `json:"data"`
	}

	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		zlog.Error().Err(err).Msg("Error decoding Blnk webhook payload")
		http.Error(w, "Error decoding webhook payload", http.StatusBadRequest)
		return
	}

	zlog.With().Str("webhook_event", payload.Event).Logger()
	log.Info().Msg("Received Blnk webhook event")

	transactionData := payload.Data

	var t Transaction
	transactionBytes, err := json.Marshal(transactionData)
	if err != nil {
		log.Error().Err(err).Msg("Error marshalling transaction data from webhook")
		http.Error(w, "Error processing transaction data in webhook", http.StatusInternalServerError)
		return
	}
	log.Info().Msgf("Transaction data: %s", string(transactionBytes))

	err = json.Unmarshal(transactionBytes, &t)
	if err != nil {
		log.Error().Err(err).Msg("Error unmarshalling transaction data from webhook")
		http.Error(w, "Error unmarshalling transaction data", http.StatusBadRequest)
		return
	}

	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now()
	}
	if t.TransactionID == "" {
		t.TransactionID = uuid.New().String()
		log.Warn().Msg("Webhook transaction data missing ID, generated a new one.")
	} else {
		log = log.With().Str("transaction_id", t.TransactionID).Logger()
	}

	log.Info().Msg("Processing transaction from Blnk webhook")

	t, err = inject(t)
	if err != nil {
		log.Error().Err(err).Msg("Error processing transaction from webhook")
		http.Error(w, fmt.Sprintf("Error processing transaction: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Transaction %s from webhook event '%s' processed successfully", t.TransactionID, payload.Event)
	log.Info().Msg("Successfully processed transaction from Blnk webhook")
}

func handleInstructions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleListInstructions(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func handleInstructionByID(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(pathParts) < 2 || pathParts[1] == "" {
		http.Error(w, "Missing instruction ID", http.StatusBadRequest)
		return
	}
	instructionIDStr := pathParts[1]

	instructionID, err := strconv.ParseInt(instructionIDStr, 10, 64)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid instruction ID: %s", instructionIDStr), http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		handleGetInstruction(w, r, instructionID)
	case http.MethodDelete:
		handleDeleteInstruction(w, r, instructionID)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func handleListInstructions(w http.ResponseWriter, r *http.Request) {
	log := zlog.With().Str("handler", "ListInstructions").Logger()
	log.Info().Msg("Received request to list instructions")

	instructions, err := GetAllInstructions()
	if err != nil {
		log.Error().Err(err).Msg("Error getting all instructions from store")
		http.Error(w, "Failed to retrieve instructions", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(instructions); err != nil {
		log.Error().Err(err).Msg("Error encoding instructions list response")
	}
}

func handleGetInstruction(w http.ResponseWriter, r *http.Request, id int64) {
	log := zlog.With().Str("handler", "GetInstruction").Int64("instruction_id", id).Logger()
	log.Info().Msg("Received request to get instruction by ID")

	instruction, err := GetInstructionByID(id)
	if err != nil {
		log.Warn().Err(err).Msg("Error getting instruction by ID from store")
		if strings.Contains(err.Error(), "not found") {
			http.Error(w, err.Error(), http.StatusNotFound)
		} else {
			http.Error(w, "Failed to retrieve instruction", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(instruction); err != nil {
		log.Error().Err(err).Msg("Error encoding instruction response")
	}
}

func handleDeleteInstruction(w http.ResponseWriter, r *http.Request, id int64) {
	log := zlog.With().Str("handler", "DeleteInstruction").Int64("instruction_id", id).Logger()
	log.Info().Msg("Received request to delete instruction")

	err := DeleteInstruction(id)
	if err != nil {
		log.Error().Err(err).Msg("Error deleting instruction from store")
		if strings.Contains(err.Error(), "not found") {
			http.Error(w, err.Error(), http.StatusNotFound)
		} else {
			http.Error(w, "Failed to delete instruction", http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func handleTransactionByID(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(pathParts) < 2 || pathParts[1] == "" {
		http.Error(w, "Missing transaction ID", http.StatusBadRequest)
		return
	}
	transactionID := pathParts[1]

	switch r.Method {
	case http.MethodGet:
		handleGetTransaction(w, r, transactionID)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func handleGetTransaction(w http.ResponseWriter, r *http.Request, transactionID string) {
	log := zlog.With().Str("handler", "GetTransaction").Str("transaction_id", transactionID).Logger()
	log.Info().Msg("Received request to get transaction by ID")

	transaction, err := getTransactionByID(transactionID)
	if err != nil {
		log.Warn().Err(err).Msg("Error getting transaction by ID")
		if strings.Contains(err.Error(), "not found") {
			http.Error(w, "Transaction not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to retrieve transaction", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(transaction); err != nil {
		log.Error().Err(err).Msg("Error encoding transaction response")
	}
}

func handleCompileAndSaveInstruction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method. Only POST is allowed.", http.StatusMethodNotAllowed)
		return
	}

	log := zlog.With().Str("handler", "CompileAndSaveInstruction").Logger()
	log.Info().Msg("Received request to compile and save instruction script")

	var requestBody struct {
		Script string `json:"script"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		log.Warn().Err(err).Msg("Error decoding /compile-and-save-instruction request body")
		http.Error(w, "Invalid request body: could not decode JSON", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(requestBody.Script) == "" {
		log.Warn().Msg("Empty script provided in /compile-and-save-instruction request")
		http.Error(w, "Missing required field: script cannot be empty", http.StatusBadRequest)
		return
	}

	ruleName, description, compiledRuleJSON, compileErr := CompileWatchScript(requestBody.Script)
	if compileErr != nil {
		http.Error(w, fmt.Sprintf("Failed to compile script: %v", compileErr), http.StatusInternalServerError)
		return
	}

	instruction, saveErr := CreateInstructionWithPrecompiledDSL(r.Context(), ruleName, requestBody.Script, description, compiledRuleJSON)
	if saveErr != nil {
		log.Error().Err(saveErr).Str("rule_name", ruleName).Msg("Failed to save compiled instruction")
		if strings.Contains(saveErr.Error(), "UNIQUE constraint failed") || strings.Contains(saveErr.Error(), "already exists") {
			http.Error(w, fmt.Sprintf("Failed to save instruction: An instruction with name '%s' already exists. %v", ruleName, saveErr), http.StatusConflict)
		} else {
			http.Error(w, fmt.Sprintf("Failed to save instruction '%s': %v", ruleName, saveErr), http.StatusInternalServerError)
		}
		return
	}

	log.Info().Int64("instruction_id", instruction.ID).Str("rule_name", ruleName).Msg("Instruction compiled and saved successfully")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(instruction); err != nil {
		log.Error().Err(err).Int64("instruction_id", instruction.ID).Msg("Error encoding successful /compile-and-save-instruction response")
	}
}

type GitStatusResponse struct {
	Configured    bool   `json:"configured"`
	RepoURL       string `json:"repo_url,omitempty"`
	Branch        string `json:"branch,omitempty"`
	LocalPath     string `json:"local_path,omitempty"`
	CurrentCommit string `json:"current_commit,omitempty"`
	RemoteCommit  string `json:"remote_commit,omitempty"`
	UpToDate      bool   `json:"up_to_date"`
	LastSync      string `json:"last_sync,omitempty"`
	Error         string `json:"error,omitempty"`
}

func handleGitStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	response := GitStatusResponse{
		Configured: globalGitManager != nil,
	}

	if globalGitManager == nil {
		response.Error = "Git repository not configured"
	} else {
		response.RepoURL = globalGitManager.RepoURL
		response.Branch = globalGitManager.Branch
		response.LocalPath = globalGitManager.LocalPath

		if currentCommit, err := globalGitManager.GetCurrentCommit(); err != nil {
			response.Error = fmt.Sprintf("Failed to get current commit: %v", err)
		} else {
			response.CurrentCommit = currentCommit
		}

		if remoteCommit, err := globalGitManager.GetRemoteCommit(); err != nil {
			zlog.Debug().Err(err).Msg("Failed to get remote commit for status")
		} else {
			response.RemoteCommit = remoteCommit
			response.UpToDate = response.CurrentCommit == response.RemoteCommit
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		zlog.Error().Err(err).Msg("Error encoding Git status response")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

type GitSyncResponse struct {
	Success       bool   `json:"success"`
	Message       string `json:"message"`
	BeforeCommit  string `json:"before_commit,omitempty"`
	AfterCommit   string `json:"after_commit,omitempty"`
	ScriptsLoaded int    `json:"scripts_loaded,omitempty"`
	Error         string `json:"error,omitempty"`
}

func handleGitSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	response := GitSyncResponse{}

	if globalGitManager == nil {
		response.Success = false
		response.Error = "Git repository not configured"
	} else {
		beforeCommit, _ := globalGitManager.GetCurrentCommit()
		response.BeforeCommit = beforeCommit

		if err := globalGitManager.CloneOrUpdate(); err != nil {
			response.Success = false
			response.Error = fmt.Sprintf("Failed to sync repository: %v", err)
			zlog.Error().Err(err).Msg("Manual Git sync failed")
		} else {
			response.Success = true
			response.Message = "Repository synced successfully"

			afterCommit, _ := globalGitManager.GetCurrentCommit()
			response.AfterCommit = afterCommit

			if beforeCommit != afterCommit {
				go func() {
					processExistingScriptsInDir(globalGitManager.LocalPath)
					zlog.Info().Msg("Processed scripts after manual Git sync")
				}()
				response.Message = "Repository synced and scripts reloaded"
			}

			zlog.Info().
				Str("before", beforeCommit).
				Str("after", afterCommit).
				Msg("Manual Git sync completed")
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		zlog.Error().Err(err).Msg("Error encoding Git sync response")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
