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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func doRequest(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	buildWatchMux().ServeHTTP(rec, req)
	return rec
}

func TestHandleInject(t *testing.T) {
	clearTransactions(t)

	rec := doRequest(t, http.MethodPost, "/inject", `{"transaction_id":"api-1","amount":100,"currency":"USD","source":"s","destination":"d"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad response: %v", err)
	}
	if resp["transaction_id"] != "api-1" {
		t.Errorf("transaction_id = %q", resp["transaction_id"])
	}

	if _, err := getTransactionByID("api-1"); err != nil {
		t.Errorf("transaction not persisted: %v", err)
	}

	// Missing ID gets one generated.
	rec = doRequest(t, http.MethodPost, "/inject", `{"amount":5}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["transaction_id"] == "" {
		t.Error("expected generated transaction_id")
	}

	// Wrong method.
	if rec := doRequest(t, http.MethodGet, "/inject", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /inject status = %d", rec.Code)
	}
	// Bad body.
	if rec := doRequest(t, http.MethodPost, "/inject", "{bad json"); rec.Code != http.StatusBadRequest {
		t.Errorf("bad body status = %d", rec.Code)
	}
}

func TestHandleBlnkWebhook(t *testing.T) {
	clearTransactions(t)

	payload := `{"event":"transaction.applied","data":{"transaction_id":"wh-1","amount":42,"currency":"NGN"}}`
	rec := doRequest(t, http.MethodPost, "/blnkwebhook", payload)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "wh-1") {
		t.Errorf("response should mention transaction id: %s", rec.Body.String())
	}
	if _, err := getTransactionByID("wh-1"); err != nil {
		t.Errorf("webhook transaction not persisted: %v", err)
	}

	// Missing transaction ID gets one generated.
	rec = doRequest(t, http.MethodPost, "/blnkwebhook", `{"event":"e","data":{"amount":1}}`)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d", rec.Code)
	}

	if rec := doRequest(t, http.MethodGet, "/blnkwebhook", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d", rec.Code)
	}
	if rec := doRequest(t, http.MethodPost, "/blnkwebhook", "{bad"); rec.Code != http.StatusBadRequest {
		t.Errorf("bad body status = %d", rec.Code)
	}
}

func TestHandleInstructionsEndpoints(t *testing.T) {
	clearInstructions(t)

	created, err := CreateInstructionWithPrecompiledDSL(context.Background(), "api-rule", "text", "desc", testRuleDSL)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// List
	rec := doRequest(t, http.MethodGet, "/instructions", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d", rec.Code)
	}
	var list []Instruction
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("bad list response: %v", err)
	}
	if len(list) != 1 || list[0].Name != "api-rule" {
		t.Errorf("unexpected list: %+v", list)
	}
	if rec := doRequest(t, http.MethodPost, "/instructions", "{}"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /instructions status = %d", rec.Code)
	}

	// Get by ID
	rec = doRequest(t, http.MethodGet, fmt.Sprintf("/instructions/%d", created.ID), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d", rec.Code)
	}
	var got Instruction
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got.ID != created.ID {
		t.Errorf("got ID %d, want %d", got.ID, created.ID)
	}

	// Errors
	if rec := doRequest(t, http.MethodGet, "/instructions/99999", ""); rec.Code != http.StatusNotFound {
		t.Errorf("missing instruction status = %d", rec.Code)
	}
	if rec := doRequest(t, http.MethodGet, "/instructions/not-a-number", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("bad id status = %d", rec.Code)
	}
	if rec := doRequest(t, http.MethodGet, "/instructions/", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("empty id status = %d", rec.Code)
	}
	if rec := doRequest(t, http.MethodPut, fmt.Sprintf("/instructions/%d", created.ID), "{}"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT status = %d", rec.Code)
	}

	// Delete
	if rec := doRequest(t, http.MethodDelete, fmt.Sprintf("/instructions/%d", created.ID), ""); rec.Code != http.StatusNoContent {
		t.Errorf("delete status = %d", rec.Code)
	}
	if rec := doRequest(t, http.MethodDelete, fmt.Sprintf("/instructions/%d", created.ID), ""); rec.Code != http.StatusNotFound {
		t.Errorf("re-delete status = %d", rec.Code)
	}
}

func TestHandleTransactionByID(t *testing.T) {
	clearTransactions(t)
	ts := time.Now().UTC().Format("2006-01-02 15:04:05")
	insertTestTransaction(t, "api-tx-1", 75, "USD", "s", "d", ts, "desc", `{"k":"v"}`)

	rec := doRequest(t, http.MethodGet, "/transactions/api-tx-1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var got Transaction
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("bad response: %v", err)
	}
	if got.TransactionID != "api-tx-1" || got.Amount != 75 {
		t.Errorf("unexpected transaction: %+v", got)
	}

	if rec := doRequest(t, http.MethodGet, "/transactions/missing-tx", ""); rec.Code != http.StatusNotFound {
		t.Errorf("missing tx status = %d", rec.Code)
	}
	if rec := doRequest(t, http.MethodGet, "/transactions/", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("empty id status = %d", rec.Code)
	}
	if rec := doRequest(t, http.MethodPost, "/transactions/api-tx-1", "{}"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d", rec.Code)
	}
}

func TestHandleCompileAndSaveInstruction(t *testing.T) {
	clearInstructions(t)

	script := `rule ApiCompileTest {
  description "test rule from api"

  when amount > 1000

  then review
       score   0.5
       reason  "large amount"
}`

	body, _ := json.Marshal(map[string]string{"script": script})
	rec := doRequest(t, http.MethodPost, "/compile-and-save-instruction", string(body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var inst Instruction
	if err := json.Unmarshal(rec.Body.Bytes(), &inst); err != nil {
		t.Fatalf("bad response: %v", err)
	}
	if inst.Name != "ApiCompileTest" || !inst.DSLJSON.Valid {
		t.Errorf("unexpected instruction: %+v", inst)
	}

	// Errors
	if rec := doRequest(t, http.MethodGet, "/compile-and-save-instruction", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d", rec.Code)
	}
	if rec := doRequest(t, http.MethodPost, "/compile-and-save-instruction", "{bad"); rec.Code != http.StatusBadRequest {
		t.Errorf("bad body status = %d", rec.Code)
	}
	if rec := doRequest(t, http.MethodPost, "/compile-and-save-instruction", `{"script":"  "}`); rec.Code != http.StatusBadRequest {
		t.Errorf("empty script status = %d", rec.Code)
	}
	if rec := doRequest(t, http.MethodPost, "/compile-and-save-instruction", `{"script":"not a valid script"}`); rec.Code != http.StatusInternalServerError {
		t.Errorf("invalid script status = %d", rec.Code)
	}
}

func TestHandleGitStatus(t *testing.T) {
	saved := globalGitManager
	defer func() { globalGitManager = saved }()

	globalGitManager = nil
	rec := doRequest(t, http.MethodGet, "/git/status", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp GitStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad response: %v", err)
	}
	if resp.Configured || resp.Error == "" {
		t.Errorf("unconfigured git should be reported: %+v", resp)
	}

	if rec := doRequest(t, http.MethodPost, "/git/status", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d", rec.Code)
	}

	// Configured but pointing at a non-repo directory: errors are reported in
	// the response body rather than failing the request.
	globalGitManager = NewGitManager("https://example.com/repo.git", "main", t.TempDir(), "", "")
	rec = doRequest(t, http.MethodGet, "/git/status", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("configured status = %d", rec.Code)
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.Configured || resp.RepoURL != "https://example.com/repo.git" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestHandleGitSync(t *testing.T) {
	saved := globalGitManager
	defer func() { globalGitManager = saved }()

	globalGitManager = nil
	rec := doRequest(t, http.MethodPost, "/git/sync", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp GitSyncResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad response: %v", err)
	}
	if resp.Success || resp.Error == "" {
		t.Errorf("unconfigured git sync should fail: %+v", resp)
	}

	if rec := doRequest(t, http.MethodGet, "/git/sync", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d", rec.Code)
	}
}
