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
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "github.com/marcboeker/go-duckdb"
	"github.com/rs/zerolog/log"
)

func updateInstructionDSL(db *sql.DB, id int64, dslJSON string) error {
	stmt, err := instructionDB.Prepare(`UPDATE instructions SET dsl_json = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;`)
	if err != nil {
		log.Error().Err(err).Int64("id", id).Msg("Error preparing update DSL statement")
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(dslJSON, id)
	if err != nil {
		log.Error().Err(err).Int64("id", id).Msg("Error executing update DSL statement")
		return err
	}
	log.Debug().Int64("id", id).Msg("Successfully updated DSL JSON for instruction")
	return nil
}

func GetInstructionByID(id int64) (Instruction, error) {
	if instructionDB == nil {
		return Instruction{}, errors.New("instruction database not initialized")
	}
	return getInstructionByIDInternal(instructionDB, id)
}

func getInstructionByIDInternal(db *sql.DB, id int64) (Instruction, error) {
	row := db.QueryRow(`
		SELECT id, name, text, description, CAST(dsl_json AS VARCHAR), created_at, updated_at
		FROM instructions
		WHERE id = ?;
	`, id)

	var i Instruction
	var desc sql.NullString
	err := row.Scan(&i.ID, &i.Name, &i.Text, &desc, &i.DSLJSON, &i.CreatedAt, &i.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Warn().Int64("id", id).Msg("Instruction not found by ID")
			return Instruction{}, fmt.Errorf("instruction with ID %d not found", id)
		}
		log.Error().Err(err).Int64("id", id).Msg("Error scanning instruction row")
		return Instruction{}, err
	}
	if desc.Valid {
		i.Description = desc.String
	}

	return i, nil
}

func GetInstructionByName(name string) (Instruction, error) {
	if instructionDB == nil {
		return Instruction{}, errors.New("instruction database not initialized")
	}

	row := instructionDB.QueryRow(`
		SELECT id, name, text, description, CAST(dsl_json AS VARCHAR), created_at, updated_at
		FROM instructions
		WHERE name = ?;
	`, name)

	var i Instruction
	var desc sql.NullString
	err := row.Scan(&i.ID, &i.Name, &i.Text, &desc, &i.DSLJSON, &i.CreatedAt, &i.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Warn().Str("name", name).Msg("Instruction not found by name")
			return Instruction{}, fmt.Errorf("instruction with name '%s' not found", name)
		}
		log.Error().Err(err).Str("name", name).Msg("Error scanning instruction row by name")
		return Instruction{}, err
	}
	if desc.Valid {
		i.Description = desc.String
	}

	return i, nil
}

func GetAllInstructions() ([]Instruction, error) {
	if instructionDB == nil {
		return nil, errors.New("instruction database not initialized")
	}

	rows, err := instructionDB.Query(`
		SELECT id, name, text, description, CAST(dsl_json AS VARCHAR), created_at, updated_at
		FROM instructions
		ORDER BY name;
	`)
	if err != nil {
		log.Error().Err(err).Msg("Error querying all instructions")
		return nil, err
	}
	defer rows.Close()

	var instructions []Instruction
	for rows.Next() {
		var i Instruction
		var desc sql.NullString
		err = rows.Scan(&i.ID, &i.Name, &i.Text, &desc, &i.DSLJSON, &i.CreatedAt, &i.UpdatedAt)
		if err != nil {
			log.Error().Err(err).Msg("Error scanning instruction row during GetAllInstructions")
			return nil, err
		}
		if desc.Valid {
			i.Description = desc.String
		}
		instructions = append(instructions, i)
	}

	if err = rows.Err(); err != nil {
		log.Error().Err(err).Msg("Error iterating instruction rows")
		return nil, err
	}

	log.Debug().Int("count", len(instructions)).Msg("Successfully retrieved all instructions")
	return instructions, nil
}

func DeleteInstruction(id int64) error {
	if instructionDB == nil {
		return errors.New("instruction database not initialized")
	}

	stmt, err := instructionDB.Prepare(`DELETE FROM instructions WHERE id = ?;`)
	if err != nil {
		log.Error().Err(err).Msg("Error preparing delete instruction statement")
		return err
	}
	defer stmt.Close()

	result, err := stmt.Exec(id)
	if err != nil {
		log.Error().Err(err).Int64("id", id).Msg("Error executing delete instruction statement")
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Error().Err(err).Int64("id", id).Msg("Error getting rows affected after delete")
	}
	if rowsAffected == 0 {
		log.Warn().Int64("id", id).Msg("Delete instruction called but no rows were affected (ID might not exist)")
		return fmt.Errorf("instruction with ID %d not found for deletion", id)
	}

	log.Info().Int64("id", id).Msg("Successfully deleted instruction")
	return nil
}

func getActiveRules() ([]Rule, error) {
	if instructionDB == nil {
		return nil, errors.New("instruction database not initialized")
	}

	rows, err := instructionDB.Query(`
		SELECT id, name, CAST(dsl_json AS VARCHAR)
		FROM instructions
		WHERE dsl_json IS NOT NULL AND dsl_json != '""'::JSON;
	`)
	if err != nil {
		log.Error().Err(err).Msg("Error querying instructions for active DSL rules")
		return nil, err
	}
	defer rows.Close()

	var rules []Rule
	for rows.Next() {
		var id int64
		var name string
		var dslJSON string

		err = rows.Scan(&id, &name, &dslJSON)
		if err != nil {
			log.Error().Err(err).Msg("Error scanning instruction row during getActiveRules")
			return nil, err
		}

		var rule Rule
		err = json.Unmarshal([]byte(dslJSON), &rule)
		if err != nil {
			log.Warn().Err(err).Int64("instruction_id", id).Str("instruction_name", name).Msg("Failed to unmarshal DSL JSON for instruction, skipping rule")
			continue
		}

		rule.Name = name
		rules = append(rules, rule)
	}

	if err = rows.Err(); err != nil {
		log.Error().Err(err).Msg("Error iterating instruction rows for active rules")
		return nil, err
	}

	// log.Debug().Int("count", len(rules)).Msg("Successfully retrieved and unmarshalled active DSL rules from instructions")
	return rules, nil
}

func GetTopInstructionsWithDSLExamples(limit int) ([]Instruction, error) {
	if instructionDB == nil {
		return nil, errors.New("instruction database not initialized")
	}

	query := `
		SELECT id, name, text, description, CAST(dsl_json AS VARCHAR), created_at, updated_at
		FROM instructions
		WHERE dsl_json IS NOT NULL AND dsl_json != '""'::JSON
		ORDER BY updated_at DESC
		LIMIT ?;
	`

	rows, err := instructionDB.Query(query, limit)
	if err != nil {
		log.Error().Err(err).Int("limit", limit).Msg("Error querying top instructions with DSL examples")
		return nil, err
	}
	defer rows.Close()

	var instructions []Instruction
	for rows.Next() {
		var i Instruction
		var desc sql.NullString
		err = rows.Scan(&i.ID, &i.Name, &i.Text, &desc, &i.DSLJSON, &i.CreatedAt, &i.UpdatedAt)
		if err != nil {
			log.Error().Err(err).Msg("Error scanning instruction row during GetTopInstructionsWithDSLExamples")
			return nil, err
		}
		if desc.Valid {
			i.Description = desc.String
		}
		if i.DSLJSON.Valid && i.DSLJSON.String != "" {
			instructions = append(instructions, i)
		}
	}

	if err = rows.Err(); err != nil {
		log.Error().Err(err).Msg("Error iterating instruction rows for GetTopInstructionsWithDSLExamples")
		return nil, err
	}

	log.Debug().Int("count", len(instructions)).Int("requested_limit", limit).Msg("Successfully retrieved top instructions with DSL examples")
	return instructions, nil
}

func CreateInstructionWithPrecompiledDSL(ctx context.Context, name, scriptText, description, compiledDSLJSON string) (Instruction, error) {
	if instructionDB == nil {
		return Instruction{}, errors.New("instruction database not initialized")
	}

	id, err := createInstructionRecord(instructionDB, name, scriptText, description)
	if err != nil {
		return Instruction{}, fmt.Errorf("failed to create instruction record for '%s': %w", name, err)
	}

	if compiledDSLJSON != "" {
		if updateErr := updateInstructionDSL(instructionDB, id, compiledDSLJSON); updateErr != nil {
			log.Error().Err(updateErr).Int64("instruction_id", id).Msg("Failed to save pre-compiled DSL for new instruction")
		}
	} else {
		log.Warn().Int64("instruction_id", id).Str("name", name).Msg("No pre-compiled DSL JSON provided; instruction created without DSL.")
	}

	finalInstruction, fetchErr := getInstructionByIDInternal(instructionDB, id)
	if fetchErr != nil {
		log.Error().Err(fetchErr).Int64("id", id).Msg("Failed to fetch newly created instruction after saving with pre-compiled DSL")
		return Instruction{ID: id, Name: name, Text: scriptText, Description: description}, fmt.Errorf("instruction '%s' (ID: %d) created with pre-compiled DSL, but failed to fetch final record: %w", name, id, fetchErr)
	}

	return finalInstruction, nil
}

func UpdateInstructionWithPrecompiledDSL(ctx context.Context, id int64, name, scriptText, description, compiledDSLJSON string) (Instruction, error) {
	if instructionDB == nil {
		return Instruction{}, errors.New("instruction database not initialized")
	}

	stmt, err := instructionDB.Prepare(`
		UPDATE instructions
		SET text = ?, description = ?, dsl_json = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?;
	`)
	if err != nil {
		log.Error().Err(err).Int64("id", id).Msg("Error preparing update instruction with precompiled DSL statement")
		return Instruction{}, err
	}
	defer stmt.Close()

	var dslForDB sql.NullString
	if compiledDSLJSON != "" {
		var jsonData map[string]interface{}
		if err := json.Unmarshal([]byte(compiledDSLJSON), &jsonData); err != nil {
			log.Error().Err(err).Int64("id", id).Str("inputDSL", compiledDSLJSON).Msg("compiledDSLJSON is not a valid JSON object")
			return Instruction{}, fmt.Errorf("compiledDSLJSON is not a valid JSON object for instruction ID %d: %w", id, err)
		}
		dslForDB = sql.NullString{String: compiledDSLJSON, Valid: true}
	} else {
		dslForDB = sql.NullString{Valid: false}
	}

	var descForDB sql.NullString
	if description != "" {
		descForDB = sql.NullString{String: description, Valid: true}
	} else {
		descForDB = sql.NullString{Valid: false}
	}

	result, err := stmt.Exec(scriptText, descForDB, dslForDB, id)
	if err != nil {
		log.Error().Err(err).Int64("id", id).Str("name", name).Msg("Error executing update instruction with precompiled DSL statement")
		return Instruction{}, err
	}

	rowsAffected, rerr := result.RowsAffected()
	if rerr != nil {
		log.Error().Err(rerr).Int64("id", id).Msg("Error getting rows affected after updating instruction with precompiled DSL")
	}
	if rowsAffected == 0 {
		log.Warn().Int64("id", id).Str("name", name).Msg("Update instruction with precompiled DSL called, but no rows were affected (ID might not exist)")
		return Instruction{}, fmt.Errorf("instruction with ID %d not found for update", id)
	}

	updatedInstruction, fetchErr := getInstructionByIDInternal(instructionDB, id)
	if fetchErr != nil {
		log.Error().Err(fetchErr).Int64("id", id).Msg("Failed to fetch instruction after updating with precompiled DSL")
		return Instruction{ID: id, Name: name, Text: scriptText, Description: description, DSLJSON: dslForDB, UpdatedAt: time.Now()},
			fmt.Errorf("instruction (ID: %d) updated with precompiled DSL, but failed to fetch final record: %w", id, fetchErr)
	}

	return updatedInstruction, nil
}
