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
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"time"

	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
)

const (
	ColorBlue = "\033[34m"
	ColorNone = "\033[0m"
)

type AnomalyMessage struct {
	Type           string                 `json:"type"`
	TransactionID  string                 `json:"transaction_id"`
	Description    string                 `json:"description"`
	RiskLevel      string                 `json:"risk_level"`
	RiskScore      float64                `json:"risk_score"`
	Verdict        string                 `json:"verdict"`
	Reason         string                 `json:"reason"`
	SourceCount    int                    `json:"source_count"`
	Timestamp      string                 `json:"timestamp"`
	AdditionalData map[string]interface{} `json:"additional_data,omitempty"`
}

var globalTunnel interface{}

var globalGitManager *GitManager

func SendAnomalyToTunnel(anomaly AnomalyMessage) error {
	if globalTunnel == nil {
		return fmt.Errorf("WebSocket tunnel not available")
	}

	tunnelValue := reflect.ValueOf(globalTunnel)
	isConnectedMethod := tunnelValue.MethodByName("IsConnected")
	if !isConnectedMethod.IsValid() {
		return fmt.Errorf("tunnel does not have IsConnected method")
	}

	result := isConnectedMethod.Call(nil)
	if len(result) == 0 || !result[0].Bool() {
		return fmt.Errorf("WebSocket tunnel not connected")
	}

	sendAnomalyMethod := tunnelValue.MethodByName("SendAnomaly")
	if !sendAnomalyMethod.IsValid() {
		return fmt.Errorf("tunnel does not have SendAnomaly method")
	}

	jsonData, err := json.Marshal(anomaly)
	if err != nil {
		return fmt.Errorf("failed to marshal anomaly: %w", err)
	}

	var tunnelAnomaly map[string]interface{}
	if err := json.Unmarshal(jsonData, &tunnelAnomaly); err != nil {
		return fmt.Errorf("failed to unmarshal anomaly: %w", err)
	}

	tunnelAnomalyType := sendAnomalyMethod.Type().In(0)
	tunnelAnomalyValue := reflect.New(tunnelAnomalyType).Elem()

	tunnelAnomalyBytes, err := json.Marshal(tunnelAnomaly)
	if err != nil {
		return fmt.Errorf("failed to marshal tunnel anomaly: %w", err)
	}

	if err := json.Unmarshal(tunnelAnomalyBytes, tunnelAnomalyValue.Addr().Interface()); err != nil {
		return fmt.Errorf("failed to unmarshal to tunnel anomaly type: %w", err)
	}

	results := sendAnomalyMethod.Call([]reflect.Value{tunnelAnomalyValue})
	if len(results) > 0 && !results[0].IsNil() {
		return results[0].Interface().(error)
	}

	return nil
}

func SetupWatchService(tunnel interface{}) {
	if err := RunWatchService(context.Background(), "8081", tunnel); err != nil {
		zlog.Fatal().Err(err).Msg("Failed to start watch service")
	}
}

func RunWatchService(ctx context.Context, port string, tunnel interface{}) error {
	globalTunnel = tunnel
	godotenv.Load()
	zlog.Logger = zlog.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	zlog.Info().Msg("Starting Blnk Watch...")

	if err := InitInstructionDB(); err != nil {
		return fmt.Errorf("failed to initialize instruction database: %w", err)
	}
	defer CloseInstructionDB()

	initializedTransactionsDB := false
	if _, err := GetDB(); err != nil {
		if err := InitTransactionsDB(); err != nil {
			return fmt.Errorf("failed to initialize transactions database: %w", err)
		}
		initializedTransactionsDB = true
	}
	if initializedTransactionsDB {
		defer CloseTransactionsDB()
	}

	if err := startRiskEvaluationWorker(); err != nil {
		return fmt.Errorf("startRiskEvaluationWorker: %w", err)
	}

	watchScriptDir := os.Getenv("WATCH_SCRIPT_DIR")

	if watchScriptDir == "" {
		watchScriptDir = "watch_scripts"
	}

	if watchScriptDir != "" {

		gitRepoURL := os.Getenv("WATCH_SCRIPT_GIT_REPO")
		if gitRepoURL != "" {
			zlog.Info().Str("repo", gitRepoURL).Msg("Git repository configured for watch scripts")

			if !IsGitInstalled() {
				return fmt.Errorf("git is not installed. please install Git to use Git repository features")
			}

			gitBranch := os.Getenv("WATCH_SCRIPT_GIT_BRANCH")
			if gitBranch == "" {
				gitBranch = "main"
			}

			gitUsername := os.Getenv("WATCH_SCRIPT_GIT_USERNAME")
			gitToken := os.Getenv("WATCH_SCRIPT_GIT_TOKEN")

			// Validate Git repository URL
			if err := ValidateGitRepo(gitRepoURL, gitUsername, gitToken); err != nil {
				return fmt.Errorf("invalid Git repository URL: %w", err)
			}

			gitManager := NewGitManager(gitRepoURL, gitBranch, watchScriptDir, gitUsername, gitToken)
			globalGitManager = gitManager

			if err := gitManager.CloneOrUpdate(); err != nil {
				return fmt.Errorf("failed to clone or update Git repository: %w", err)
			}

			go processExistingScriptsInDir(watchScriptDir)

			gitManager.StartPeriodicSync()

			if err := gitManager.StartWatching(); err != nil {
				zlog.Error().Err(err).Msg("Failed to start Git repository file watcher")
			}

		} else {
			go processExistingScriptsInDir(watchScriptDir)
			go watchScriptDirectory(watchScriptDir)
		}
	}

	if port == "" {
		port = "8081"
	}

	server := &http.Server{
		Addr:    ":" + port,
		Handler: buildWatchMux(),
	}

	go func() {
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			zlog.Error().Err(err).Msg("Failed to shut down watch service")
		}
	}()

	zlog.Info().Msgf("Server listening on port %s", port)
	err := server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("failed to start server: %w", err)
	}

	return nil
}

func buildWatchMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/inject", handleInject)
	mux.HandleFunc("/blnkwebhook", handleBlnkWebhook)
	mux.HandleFunc("/instructions", handleInstructions)
	mux.HandleFunc("/instructions/", handleInstructionByID)
	mux.HandleFunc("/transactions/", handleTransactionByID)
	mux.HandleFunc("/compile-and-save-instruction", handleCompileAndSaveInstruction)
	mux.HandleFunc("/git/status", handleGitStatus)
	mux.HandleFunc("/git/sync", handleGitSync)
	return mux
}
