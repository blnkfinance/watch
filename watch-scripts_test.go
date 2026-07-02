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
	"database/sql"
	"strings"
	"testing"
)

const testRuleDSL = `{"id":1,"name":"test-rule","when":[{"field":"amount","op":"gt","value":1000}],"then":{"verdict":"review","score":0.8,"reason":"large amount"}}`

func TestInstructionCRUD(t *testing.T) {
	clearInstructions(t)
	ctx := context.Background()

	created, err := CreateInstructionWithPrecompiledDSL(ctx, "crud-rule", "watch script text", "desc", testRuleDSL)
	if err != nil {
		t.Fatalf("CreateInstructionWithPrecompiledDSL: %v", err)
	}
	if created.ID <= 0 || created.Name != "crud-rule" || !created.DSLJSON.Valid {
		t.Fatalf("unexpected created instruction: %+v", created)
	}

	byID, err := GetInstructionByID(created.ID)
	if err != nil {
		t.Fatalf("GetInstructionByID: %v", err)
	}
	if byID.Name != "crud-rule" || byID.Description != "desc" {
		t.Errorf("unexpected instruction by ID: %+v", byID)
	}

	byName, err := GetInstructionByName("crud-rule")
	if err != nil {
		t.Fatalf("GetInstructionByName: %v", err)
	}
	if byName.ID != created.ID {
		t.Errorf("byName.ID = %d, want %d", byName.ID, created.ID)
	}

	all, err := GetAllInstructions()
	if err != nil {
		t.Fatalf("GetAllInstructions: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("expected 1 instruction, got %d", len(all))
	}

	updated, err := UpdateInstructionWithPrecompiledDSL(ctx, created.ID, "crud-rule", "new text", "new desc", testRuleDSL)
	if err != nil {
		t.Fatalf("UpdateInstructionWithPrecompiledDSL: %v", err)
	}
	if updated.Text != "new text" || updated.Description != "new desc" {
		t.Errorf("update not persisted: %+v", updated)
	}

	// Update with empty DSL clears it.
	updated, err = UpdateInstructionWithPrecompiledDSL(ctx, created.ID, "crud-rule", "text2", "", "")
	if err != nil {
		t.Fatalf("update with empty DSL: %v", err)
	}
	if updated.DSLJSON.Valid && updated.DSLJSON.String != "" {
		t.Errorf("expected DSL cleared, got %+v", updated.DSLJSON)
	}

	// Update with invalid JSON is rejected.
	if _, err := UpdateInstructionWithPrecompiledDSL(ctx, created.ID, "crud-rule", "t", "d", "{not json"); err == nil {
		t.Error("invalid DSL JSON should error")
	}

	// Update of a missing ID errors.
	if _, err := UpdateInstructionWithPrecompiledDSL(ctx, 99999, "nope", "t", "d", testRuleDSL); err == nil {
		t.Error("update of missing instruction should error")
	}

	if err := DeleteInstruction(created.ID); err != nil {
		t.Fatalf("DeleteInstruction: %v", err)
	}
	if err := DeleteInstruction(created.ID); err == nil {
		t.Error("deleting missing instruction should error")
	}
	if _, err := GetInstructionByID(created.ID); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not found error, got %v", err)
	}
	if _, err := GetInstructionByName("crud-rule"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not found error by name, got %v", err)
	}
}

func TestCreateInstructionWithoutDSL(t *testing.T) {
	clearInstructions(t)

	created, err := CreateInstructionWithPrecompiledDSL(context.Background(), "no-dsl", "text", "", "")
	if err != nil {
		t.Fatalf("create without DSL: %v", err)
	}
	if created.DSLJSON.Valid && created.DSLJSON.String != "" {
		t.Errorf("expected no DSL, got %+v", created.DSLJSON)
	}
}

func TestGetActiveRules(t *testing.T) {
	clearInstructions(t)
	ctx := context.Background()

	if _, err := CreateInstructionWithPrecompiledDSL(ctx, "active-1", "text", "", testRuleDSL); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Instruction without DSL should not appear as an active rule.
	if _, err := CreateInstructionWithPrecompiledDSL(ctx, "inactive", "text", "", ""); err != nil {
		t.Fatalf("create: %v", err)
	}

	rules, err := getActiveRules()
	if err != nil {
		t.Fatalf("getActiveRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 active rule, got %d", len(rules))
	}
	// Rule name comes from the instruction record, not the DSL payload.
	if rules[0].Name != "active-1" {
		t.Errorf("rule name = %q, want %q", rules[0].Name, "active-1")
	}
	if len(rules[0].When) != 1 || rules[0].Then.Verdict != "review" {
		t.Errorf("rule payload mismatch: %+v", rules[0])
	}
}

func TestGetTopInstructionsWithDSLExamples(t *testing.T) {
	clearInstructions(t)
	ctx := context.Background()

	for _, name := range []string{"ex-1", "ex-2", "ex-3"} {
		if _, err := CreateInstructionWithPrecompiledDSL(ctx, name, "text", "", testRuleDSL); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	if _, err := CreateInstructionWithPrecompiledDSL(ctx, "ex-no-dsl", "text", "", ""); err != nil {
		t.Fatalf("create: %v", err)
	}

	top, err := GetTopInstructionsWithDSLExamples(2)
	if err != nil {
		t.Fatalf("GetTopInstructionsWithDSLExamples: %v", err)
	}
	if len(top) != 2 {
		t.Errorf("expected 2 instructions, got %d", len(top))
	}
	for _, inst := range top {
		if !inst.DSLJSON.Valid || inst.DSLJSON.String == "" {
			t.Errorf("instruction %s has no DSL", inst.Name)
		}
	}
}

func TestInstructionFunctionsWithNilDB(t *testing.T) {
	saved := instructionDB
	instructionDB = nil
	defer func() { instructionDB = saved }()

	if _, err := GetInstructionByID(1); err == nil {
		t.Error("GetInstructionByID with nil db should error")
	}
	if _, err := GetInstructionByName("x"); err == nil {
		t.Error("GetInstructionByName with nil db should error")
	}
	if _, err := GetAllInstructions(); err == nil {
		t.Error("GetAllInstructions with nil db should error")
	}
	if err := DeleteInstruction(1); err == nil {
		t.Error("DeleteInstruction with nil db should error")
	}
	if _, err := getActiveRules(); err == nil {
		t.Error("getActiveRules with nil db should error")
	}
	if _, err := GetTopInstructionsWithDSLExamples(5); err == nil {
		t.Error("GetTopInstructionsWithDSLExamples with nil db should error")
	}
	if _, err := CreateInstructionWithPrecompiledDSL(context.Background(), "n", "t", "d", ""); err == nil {
		t.Error("CreateInstructionWithPrecompiledDSL with nil db should error")
	}
	if _, err := UpdateInstructionWithPrecompiledDSL(context.Background(), 1, "n", "t", "d", ""); err == nil {
		t.Error("UpdateInstructionWithPrecompiledDSL with nil db should error")
	}
}

func TestGetActiveRulesSkipsMalformedDSL(t *testing.T) {
	clearInstructions(t)

	// Insert a row whose dsl_json is valid JSON but not a valid Rule shape:
	// unmarshal succeeds only for objects, so a JSON string payload is skipped.
	var id int64
	err := instructionDB.QueryRow(
		`INSERT INTO instructions (name, text, description, dsl_json) VALUES (?, ?, ?, ?) RETURNING id`,
		"malformed", "text", "", `"just a string"`).Scan(&id)
	if err != nil {
		t.Fatalf("insert malformed: %v", err)
	}

	rules, err := getActiveRules()
	if err != nil {
		t.Fatalf("getActiveRules: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("malformed DSL should be skipped, got %+v", rules)
	}
}

func TestUpdateInstructionDSL(t *testing.T) {
	clearInstructions(t)

	id, err := createInstructionRecord(instructionDB, "dsl-upd", "text", "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := updateInstructionDSL(instructionDB, id, testRuleDSL); err != nil {
		t.Fatalf("updateInstructionDSL: %v", err)
	}
	got, err := GetInstructionByID(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.DSLJSON.Valid {
		t.Fatal("DSL not saved")
	}
	var check sql.NullString = got.DSLJSON
	if !strings.Contains(check.String, "test-rule") {
		t.Errorf("DSL content mismatch: %s", check.String)
	}
}
