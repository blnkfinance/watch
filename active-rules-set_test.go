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
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const testScriptWithAggrConds_1 = `rule StructuringDetection {
    description "Detect multiple small deposits intended to evade limits"

    when amount < 10000
    and count(when source == $current.source, "PT24H") >= 3
    and sum(amount when source == $current.source, "PT24H") > 25000

    then review
         score   0.8
         reason  "Possible structuring"
}`

const testScriptWithAggrConds_2 = `rule StructuringDetectionUpdate {
    description "Detect multiple small deposits intended to evade limits"

	when amount < 10000
	and count(when source == $current.source, "PT24H") >= 3

	then review
	     score   0.8
	     reason  "Possible structuring"
}`

func createRuleModification(t *testing.T, ruleID *int64) {
	t.Helper()

	name, desc, ruleJSON, err := CompileWatchScript(testScriptWithAggrConds_1)
	if err != nil {
		t.Fatalf("failed to compile testRuleWithAggrConds %v", err)
	}

	ctx := context.Background()
	i, err := CreateInstructionWithPrecompiledDSL(
		ctx, name, testScriptWithAggrConds_1,
		desc, ruleJSON,
	)
	if err != nil {
		t.Fatalf("CreateInstructionWithPrecompiledDSL: %v", err)
	}
	*ruleID = i.ID
}

func updateRuleModification(t *testing.T, ruleID *int64) {
	t.Helper()
	ctx := context.Background()

	name, desc, ruleJSON, err := CompileWatchScript(testScriptWithAggrConds_2)
	if err != nil {
		t.Fatalf("CompileWatchScript: %v", err)
	}
	_, err = UpdateInstructionWithPrecompiledDSL(ctx, *ruleID, name, testScriptWithAggrConds_2, desc, ruleJSON)
	if err != nil {
		t.Fatalf("UpdateInstructionWithPrecompiledDSL: %v", err)
	}
}

func deleteRuleModification(t *testing.T, ruleID *int64) {
	t.Helper()

	path := fmt.Sprintf("/instructions/%d", *ruleID)
	if rec := doRequest(t, http.MethodDelete, path, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d", rec.Code)
	}
}

// TestActiveRulesSet_EndToEnd verifies the end-to-end behaviour of [activeRulesSet].
// It simulates a batch of transaction processing and verifies that any updates to the
// rules in the DB are correctly reflected in the [globalActiveRulesSet] during transaction processing.
func TestActiveRulesSet_EndToEnd(t *testing.T) {
	t.Cleanup(func() {
		clearInstructions(t)
		clearTransactions(t)
		globalActiveRulesSet.clear()
	})

	txns := make([]Transaction, 10)
	for i := range txns {
		txns[i] = Transaction{
			ID:     int64(i + 1),
			Amount: float64((i + 1) * 1000),
			Source: "s",
			TransactionID: fmt.Sprint(txns[i].ID),
		}
		ts := time.Now().UTC().Format("2006-01-02 15:04:05")
		insertTestTransaction(t, txns[i].TransactionID, txns[i].Amount, "USD", txns[i].Source, "d", ts, "", "")
	}

	var ruleId int64

	modificationMap := map[int]func(*testing.T, *int64){
		0: createRuleModification,
		6: updateRuleModification,
		8: deleteRuleModification,
	}

	var rulesModified bool
	var expRulesSet *activeRulesSet

	for i, txn := range txns {
		if rulesModified {
			testExpectedRulesSet(t, expRulesSet)
			rulesModified = false
		}
		if modifyingFn, ok := modificationMap[i]; ok {
			modifyingFn(t, &ruleId)
			rulesModified = true
			expRulesSet = newActiveRulesSet()

			if err := expRulesSet.populate(); err != nil {
				t.Fatalf("populate expRuleSet: %v", err)
			}
		}

		err := processTransactionRiskEvaluation(txn)
		if err != nil {
			t.Errorf("Failed to process transaction risk evaluation: %v", err)
		}
	}
}

// TestActiveRulesSet_CreateRuleInvalidates verifies that creating a new rule invalidates the in-memory
// globalActiveRulesSet. It exercises all viable paths for creating a new rule (instruction), including via
// direct API calls and through any helper functions provided by the package. It also tests
// that the global active rules set and aggregate condition is correctly rebuilt after invalidation.
func TestActiveRulesSet_CreateRuleInvalidates(t *testing.T) {

	t.Cleanup(func() {
		clearInstructions(t)
		globalActiveRulesSet.clear()
	})

	t.Run("when new instruction is created with pre-compiled DSL", func(t *testing.T) {
		t.Cleanup(func() {
			clearInstructions(t)
			globalActiveRulesSet.clear()
		})

		name, desc, ruleJSON, err := CompileWatchScript(testScriptWithAggrConds_1)
		if err != nil {
			t.Fatalf("failed to compile testRuleWithAggrConds %v", err)
		}

		ctx := context.Background()
		_, err = CreateInstructionWithPrecompiledDSL(ctx, name, testScriptWithAggrConds_1, desc, ruleJSON)
		if err != nil {
			t.Fatalf("CreateInstructionWithPrecompiledDSL: %v", err)
		}

		invalidatedCount := globalActiveRulesSet.invalidatedCount.Load()
		if invalidatedCount != 2 {
			t.Errorf("expected globalActiveRulesSet.invalidatedCount to be 2, got: %d", invalidatedCount)
		}

		if globalActiveRulesSet.isValid() {
			t.Errorf("expected globalActiveRulesSet to be invalid")
		}

		testPopulateActiveRulesSet(t)
	})
	t.Run("when new instruction is created via API call", func(t *testing.T) {
		t.Cleanup(func() {
			clearInstructions(t)
			globalActiveRulesSet.clear()
		})

		body, _ := json.Marshal(map[string]string{"script": testScriptWithAggrConds_1})
		rec := doRequest(t, http.MethodPost, "/compile-and-save-instruction", string(body))
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		invalidatedCount := globalActiveRulesSet.invalidatedCount.Load()
		if invalidatedCount != 2 {
			t.Errorf("expected globalActiveRulesSet.invalidatedCount to be 2, got: %d", invalidatedCount)
		}

		if globalActiveRulesSet.isValid() {
			t.Errorf("expected globalActiveRulesSet to be invalid")
		}

		testPopulateActiveRulesSet(t)
	})
}

// TestActiveRulesSet_UpdateRuleInvalidates checks that updating a rule in the DB invalidates the
// in-memory globalActiveRulesSet. It then checks that the rules set is correctly populated with the
// updated rule (and aggrConds)
func TestActiveRulesSet_UpdateRuleInvalidates(t *testing.T) {

	t.Cleanup(func() {
		clearInstructions(t)
		globalActiveRulesSet.clear()
	})

	ruleName, desc, ruleJSON, err := CompileWatchScript(testScriptWithAggrConds_1)
	if err != nil {
		t.Fatalf("CompileWatchScript: %v", err)
	}

	t.Run("when an instruction is updated", func(t *testing.T) {
		t.Cleanup(func() {
			clearInstructions(t)
			globalActiveRulesSet.clear()
		})

		i, err := createInstructionRecord(instructionDB, ruleName, testScriptWithAggrConds_1, desc)
		if err != nil {
			t.Fatalf("createInstructionRecord: %v", err)
		}
		err = updateInstructionDSL(instructionDB, i, ruleJSON)
		if err != nil {
			t.Fatalf("updateInstructionDSL: %v", err)
		}

		invalidatedCount := globalActiveRulesSet.invalidatedCount.Load()
		if invalidatedCount != 2 {
			t.Errorf("expected globalActiveRulesSet.invalidatedCount to be 2, got: %d", invalidatedCount)
		}

		if globalActiveRulesSet.isValid() {
			t.Errorf("expected globalActiveRulesSet to be invalid")
		}

		testPopulateActiveRulesSet(t)
	})

	t.Run("UpdateInstructionWithPrecompiledDSL", func(t *testing.T) {
		t.Cleanup(func() {
			clearInstructions(t)
			globalActiveRulesSet.clear()
		})

		i, err := createInstructionRecord(instructionDB, ruleName, testScriptWithAggrConds_1, desc)
		if err != nil {
			t.Fatalf("createInstructionRecord: %v", err)
		}
		ctx := context.Background()
		_, err = UpdateInstructionWithPrecompiledDSL(ctx, i, ruleName, testScriptWithAggrConds_1, desc, ruleJSON)
		if err != nil {
			t.Fatalf("UpdateInstructionWithPrecompiledDSL: %v", err)
		}

		invalidatedCount := globalActiveRulesSet.invalidatedCount.Load()
		if invalidatedCount != 2 {
			t.Errorf("expected globalActiveRulesSet.invalidatedCount to be 2, got: %d", invalidatedCount)
		}

		if globalActiveRulesSet.isValid() {
			t.Errorf("expected globalActiveRulesSet to be invalid")
		}

		testPopulateActiveRulesSet(t)
	})
}

// TestActiveRulesSet_DeleteRuleInvalidates checks that deleting a rule invalidates the in-memory
// globalActiveRulesSet. It then checks to make sure the rules set is repopulated so that the
// deleted rule (and aggrConds) is not present in the rules set.
func TestActiveRulesSet_DeleteRuleInvalidates(t *testing.T) {

	t.Cleanup(func() {
		clearInstructions(t)
		globalActiveRulesSet.clear()
	})

	name, desc, ruleJSON, err := CompileWatchScript(testScriptWithAggrConds_1)
	if err != nil {
		t.Fatalf("failed to compile testRuleWithAggrConds %v", err)
	}

	tests := []struct {
		name       string
		deleteFunc func(t *testing.T, ruleId int64)
	}{
		{
			name: "DeleteInstruction",
			deleteFunc: func(t *testing.T, ruleId int64) {
				t.Helper()
				err := DeleteInstruction(ruleId)
				if err != nil {
					t.Fatalf("DeleteInstruction: %v", err)
				}
			},
		},
		{
			name: "API Call",
			deleteFunc: func(t *testing.T, ruleId int64) {
				t.Helper()
				path := fmt.Sprintf("/instructions/%d", ruleId)
				if rec := doRequest(t, http.MethodDelete, path, ""); rec.Code != http.StatusNoContent {
					t.Fatalf("delete status = %d", rec.Code)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(func() {
				clearInstructions(t)
				globalActiveRulesSet.clear()
			})

			// create an instruction
			ctx := context.Background()
			i, err := CreateInstructionWithPrecompiledDSL(ctx, name, testScriptWithAggrConds_1, desc, ruleJSON)
			if err != nil {
				t.Fatalf("CreateInstructionWithPrecompiledDSL: %v", err)
			}

			invalidatedCount := globalActiveRulesSet.invalidatedCount.Load()
			if invalidatedCount != 2 {
				t.Errorf("expected globalActiveRulesSet.invalidatedCount to be 2, got: %d", invalidatedCount)
			}

			if globalActiveRulesSet.isValid() {
				t.Errorf("expected globalActiveRulesSet to be invalid")
			}

			testPopulateActiveRulesSet(t)

			tt.deleteFunc(t, i.ID)

			invalidatedCount = globalActiveRulesSet.invalidatedCount.Load()
			if invalidatedCount != 3 {
				t.Errorf("expected globalActiveRulesSet.invalidatedCount to be 3, got: %d", invalidatedCount)
			}

			if globalActiveRulesSet.isValid() {
				t.Errorf("expected globalActiveRulesSet to be invalid")
			}

			testPopulateActiveRulesSet(t)
		})
	}
}

// testPopulateActiveRulesSet tests that [activeRulesSet.populate] correctly populates the globalActiveRulesSet
// after any invalidation. globalActiveRulesSet should be invalid when [testPopulateActiveRulesSet] is called.
// It populates the globalActiveRulesSet and builds the expected rules set state
// manually, via [getActiveRules] and [buildAggregateConds]. It then calls [testExpectedRulesSet] to verify
// the rules set state.
func testPopulateActiveRulesSet(t *testing.T) {
	t.Helper()

	err := globalActiveRulesSet.populate()
	if err != nil {
		t.Fatalf("error populating globalActiveRulesSet: %v", err)
	}

	rules, err := getActiveRules()
	if err != nil {
		t.Fatalf("error getting active rules: %v", err)
	}

	// expRuleSet will have the fields invalidatedCount and level default to 0.
	// this means expRuleSet is valid. This is important, because testExpectedRulesSet
	// will compare the validity state of the expected rule set and the global active
	// rules set
	expRulesSet := &activeRulesSet{
		rules:     rules,
		aggrConds: buildAggregateConds(rules),
	}

	testExpectedRulesSet(t, expRulesSet)
}

func testExpectedRulesSet(t *testing.T, expRuleSet *activeRulesSet) {
	t.Helper()

	if expRuleSet == nil {
		t.Fatal("expected rules set is nil")
	}

	if globalActiveRulesSet.isValid() != expRuleSet.isValid() {
		t.Errorf("expected rule set validity to be: %v, got: %v", expRuleSet.isValid(), globalActiveRulesSet.isValid())
	}
	if !reflect.DeepEqual(globalActiveRulesSet.rules, expRuleSet.rules) {
		t.Errorf("expected active rules to be: %+v, got: %+v", expRuleSet.rules, globalActiveRulesSet.rules)
	}
	if !reflect.DeepEqual(globalActiveRulesSet.aggrConds, expRuleSet.aggrConds) {
		t.Errorf("expected aggrConds to be: %+v, got: %+v", expRuleSet.aggrConds, globalActiveRulesSet.aggrConds)
	}
}

// TestActiveRulesSet_CreateInstructionRecordDoesNotInvalidate tests that [createInstructionRecord]
// does not invalidate the active rules set, since it doesn't create an active rule.
func TestActiveRulesSet_CreateInstructionRecordDoesNotInvalidate(t *testing.T) {
	t.Cleanup(func() {
		clearInstructions(t)
		globalActiveRulesSet.clear()
	})

	name, description, ruleJSON, err := CompileWatchScript(testScriptWithAggrConds_1)
	if err != nil {
		t.Fatalf("CompileWatchScript: %v", err)
	}

	ctx := context.Background()
	if _, err := CreateInstructionWithPrecompiledDSL(ctx, name, testScriptWithAggrConds_1, description, ruleJSON); err != nil {
		t.Fatalf("CreateInstructionWithPrecompiledDSL: %v", err)
	}

	testPopulateActiveRulesSet(t)

	invalidatedCount := globalActiveRulesSet.invalidatedCount.Load()

	// createInstructionRecord shouldn't invalidate the active rules set
	if _, err := createInstructionRecord(instructionDB, "uncompiled-rule", "script", "description"); err != nil {
		t.Fatalf("createInstructionRecord: %v", err)
	}

	if got := globalActiveRulesSet.invalidatedCount.Load(); got != invalidatedCount {
		t.Errorf("createInstructionRecord changed invalidatedCount from %d to %d", invalidatedCount, got)
	}

	if !globalActiveRulesSet.isValid() {
		t.Errorf("expected globalActiveRulesSet to remain valid after createInstructionRecord")
	}
}

// TestActiveRulesSet_ConcurrentModification tests that concurrent modifications
// to the active rules, correctly update the invalidated count of the active rules set.
// and that the active rules set is subsequently correctly populated.
func TestActiveRulesSet_ConcurrentModification(t *testing.T) {
	t.Cleanup(func() {
		clearInstructions(t)
		globalActiveRulesSet.clear()
	})

	type ruleToCreate struct {
		name        string
		script      string
		description string
		ruleJSON    string
	}

	rules := make([]ruleToCreate, 2)

	for i, script := range []string{testScriptWithAggrConds_1, testScriptWithAggrConds_2} {
		name, description, ruleJSON, err := CompileWatchScript(script)
		if err != nil {
			t.Fatalf("CompileWatchScript: %v", err)
		}

		rules[i] = ruleToCreate{
			name:        name,
			script:      script,
			description: description,
			ruleJSON:    ruleJSON,
		}
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(rules))
	
	for _, rule := range rules {
		wg.Add(1)
		go func(rule ruleToCreate) {
			defer wg.Done()
			_, err := CreateInstructionWithPrecompiledDSL(context.Background(), rule.name, rule.script, rule.description, rule.ruleJSON) 
			if err != nil {
				errChan <- err
				return
			}
		}(rule)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		if err != nil {
			t.Fatalf("CreateInstructionWithPrecompiledDSL: %v", err)
		}
	}

	if got := globalActiveRulesSet.invalidatedCount.Load(); got != 3 {
		t.Errorf("invalidated count = %d, want 3", got)
	}
	if globalActiveRulesSet.isValid() {
		t.Errorf("expected globalActiveRulesSet to be invalid")
	}

	testPopulateActiveRulesSet(t)
}

// TestActiveRulesSet_PopulateReturnsErrorOnDatabaseFailure verifies that populate()
// returns an error when the database query fails (e.g., connection error). It also
// verifies that the rules set remains invalid after a failed populate attempt.
func TestActiveRulesSet_PopulateReturnsErrorOnDatabaseFailure(t *testing.T) {
	t.Cleanup(func() {
		clearInstructions(t)
		globalActiveRulesSet.clear()
	})

	// Create an invalid rules set state
	globalActiveRulesSet.invalidate()

	// Store original database and replace with nil to simulate connection failure
	// This will cause getActiveRules() to fail
	originalDB := instructionDB
	instructionDB = nil
	defer func() {
		instructionDB = originalDB
	}()

	// Attempt to populate should return an error
	err := globalActiveRulesSet.populate()
	if err == nil {
		t.Fatal("expected populate() to return an error, but got nil")
	}

	// Verify error message contains expected context
	if !strings.Contains(err.Error(), "getActiveRules") {
		t.Error("expected error message to contain 'getActiveRules'")
	}

	// Verify the rules set remains invalid after failed populate
	if globalActiveRulesSet.isValid() {
		t.Error("expected globalActiveRulesSet to remain invalid after failed populate")
	}
}
