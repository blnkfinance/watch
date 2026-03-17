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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

type Action struct {
	Verdict string  `json:"verdict"`
	Score   float64 `json:"score"`
	Reason  string  `json:"reason"`
}

type SimpleCond struct {
	Field string      `json:"field"`
	Op    string      `json:"op"`
	Value interface{} `json:"value"`
}

type AggregateCond struct {
	Type       string     `json:"type"` // always "aggregate"
	Metric     string     `json:"metric"`
	TimeWindow string     `json:"time_window"`
	Op         string     `json:"op"`
	Value      float64    `json:"value"`
	Filter     SimpleCond `json:"filter"`
}

type TimeFunctionCond struct {
	Type     string      `json:"type"` // always "time_function"
	Function string      `json:"function"`
	Field    string      `json:"field"`
	Op       string      `json:"op"`
	Value    interface{} `json:"value"`
}

type PreviousTransactionCond struct {
	Type       string                 `json:"type"` // always "previous_transaction"
	TimeWindow string                 `json:"time_window"`
	Match      map[string]interface{} `json:"match"`
}

type LogicalCond struct {
	Type     string      `json:"type"`     // always "logical"
	Operator string      `json:"operator"` // "and" or "or"
	Left     interface{} `json:"left"`     // nested condition
	Right    interface{} `json:"right"`    // nested condition
}

type Rule struct {
	ID   int               `json:"id"`   // optional
	Name string            `json:"name"` // optional
	When []json.RawMessage `json:"when"` // raw; we detect type at runtime
	Then Action            `json:"then"`
}

type RiskVerdict struct {
	RuleID  int     `json:"rule_id"`
	Verdict string  `json:"verdict"`
	Score   float64 `json:"score"`
	Reason  string  `json:"reason"`
}

func EvaluateRules(txn map[string]any, rules []Rule, aggContext map[string]float64) ([]RiskVerdict, error) {
	var out []RiskVerdict
	for _, r := range rules {
		ok, err := ruleApplies(txn, r, aggContext)
		if err != nil {
			log.Error().Err(err).Int("rule_id", r.ID).Msg("Error evaluating rule condition")
			continue
		}

		if ok {
			out = append(out, RiskVerdict{
				RuleID:  r.ID,
				Verdict: r.Then.Verdict,
				Score:   r.Then.Score,
				Reason:  r.Then.Reason,
			})
		}
	}
	return out, nil
}

func BuildAggContext(ctx context.Context, db *sql.DB, txn map[string]any, rules []Rule) (map[string]float64, error) {
	aggContext := make(map[string]float64)
	specs := make(map[string]AggregateCond)

	for _, r := range rules {
		for _, raw := range r.When {
			var probe struct {
				Type string `json:"type"`
			}
			_ = json.Unmarshal(raw, &probe)
			if probe.Type != "aggregate" {
				continue
			}
			var ac AggregateCond
			if err := json.Unmarshal(raw, &ac); err != nil {
				return nil, err
			}
			resolved, ok := resolvePlaceholder(ac.Filter.Value, txn)
			if !ok {
				continue
			}
			key := aggKey(ac, fmt.Sprint(resolved))
			specs[key] = ac
		}
	}

	for k, spec := range specs {
		v, err := runAggregateQuery(ctx, db, txn, spec)
		if err != nil {
			return nil, err
		}
		aggContext[k] = v
	}
	return aggContext, nil
}

func ruleApplies(tx map[string]any, r Rule, agg map[string]float64) (bool, error) {
	for _, raw := range r.When {
		var probe struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(raw, &probe)
		var passed bool
		var err error
		switch probe.Type {
		case "aggregate":
			var ac AggregateCond
			if err = json.Unmarshal(raw, &ac); err != nil {
				return false, err
			}
			passed, err = evalAggregate(tx, ac, agg)
		case "time_function":
			var tc TimeFunctionCond
			if err = json.Unmarshal(raw, &tc); err != nil {
				return false, err
			}
			passed, err = evalTimeFunction(tx, tc)
		case "previous_transaction":
			var pc PreviousTransactionCond
			if err = json.Unmarshal(raw, &pc); err != nil {
				return false, err
			}
			passed, err = evalPreviousTransaction(tx, pc)
		case "logical":
			var lc LogicalCond
			if err = json.Unmarshal(raw, &lc); err != nil {
				return false, err
			}
			passed, err = evalLogical(tx, lc, agg)
		default:
			var sc SimpleCond
			if err = json.Unmarshal(raw, &sc); err != nil {
				return false, err
			}
			passed, err = evalSimple(tx, sc)
		}
		if err != nil {
			return false, err
		}
		if !passed {
			return false, nil
		}
	}
	return true, nil
}

func evalSimple(tx map[string]any, c SimpleCond) (bool, error) {
	got, ok := dig(tx, c.Field)
	if !ok {
		return false, nil
	}

	valueToCompare, valueIsResolvableOrLiteral := resolvePlaceholder(c.Value, tx)
	if !valueIsResolvableOrLiteral {
		return false, nil
	}

	switch c.Op {
	case "eq", "ne", "gt", "gte", "lt", "lte":
		return compareScalar(got, c.Op, valueToCompare)
	case "in", "not_in":
		return compareList(got, c.Op, valueToCompare)
	case "regex", "not_regex":
		return compareRegex(got, c.Op, valueToCompare)
	default:
		return false, fmt.Errorf("unsupported op: %s", c.Op)
	}
}

func compareScalar(got any, op string, want any) (bool, error) {
	g, gOK := toFloat(got)
	w, wOK := toFloat(want)
	if gOK && wOK {
		switch op {
		case "eq":
			return g == w, nil
		case "ne":
			return g != w, nil
		case "gt":
			return g > w, nil
		case "gte":
			return g >= w, nil
		case "lt":
			return g < w, nil
		case "lte":
			return g <= w, nil
		}
	}
	gs := fmt.Sprint(got)
	ws := fmt.Sprint(want)
	switch op {
	case "eq":
		return gs == ws, nil
	case "ne":
		return gs != ws, nil
	default:
		return false, nil
	}
}

func compareList(got any, op string, list any) (bool, error) {
	arr, ok := list.([]any)
	if !ok {
		return false, errors.New("value must be array for in/not_in")
	}
	g := fmt.Sprint(got)
	found := false
	for _, v := range arr {
		if g == fmt.Sprint(v) {
			found = true
			break
		}
	}
	if op == "in" {
		return found, nil
	}
	return !found, nil
}

func compareRegex(got any, op string, pattern any) (bool, error) {
	p, ok := pattern.(string)
	if !ok {
		return false, errors.New("regex pattern must be string")
	}
	re, err := regexp.Compile(p)
	if err != nil {
		return false, err
	}
	matched := re.MatchString(fmt.Sprint(got))
	if op == "regex" {
		return matched, nil
	}
	return !matched, nil
}

func evalAggregate(tx map[string]any, ac AggregateCond, agg map[string]float64) (bool, error) {
	filterVal, found := resolvePlaceholder(ac.Filter.Value, tx)
	if !found {
		return false, nil
	}

	key := aggKey(ac, fmt.Sprint(filterVal))
	v, ok := agg[key]
	if !ok {
		return false, fmt.Errorf("internal error: aggregate value missing for key %s despite resolved placeholder", key)
	}
	return compareScalar(v, ac.Op, ac.Value)
}

func runAggregateQuery(ctx context.Context, db *sql.DB, tx map[string]any, ac AggregateCond) (float64, error) {
	filterVal, ok := resolvePlaceholder(ac.Filter.Value, tx)
	if !ok {
		return 0, nil
	}

	if filterVal == nil {
		log.Debug().
			Str("field", ac.Filter.Field).
			Msg("Filter value is nil, treating aggregate as 0")
		return 0, nil
	}

	metricExpr := map[string]string{
		"count": "COUNT(*)",
		"sum":   "COALESCE(SUM(amount), 0)",
		"avg":   "COALESCE(AVG(amount), 0)",
		"max":   "COALESCE(MAX(amount), 0)",
		"min":   "COALESCE(MIN(amount), 0)",
	}[ac.Metric]
	if metricExpr == "" {
		return 0, fmt.Errorf("unsupported metric %s", ac.Metric)
	}

	dur, err := parseISODuration(ac.TimeWindow)
	if err != nil {
		return 0, err
	}
	start := time.Now().Add(-dur)

	startTimeStr := start.UTC().Format("2006-01-02 15:04:05")

	sqlStr := fmt.Sprintf(`
		WITH filtered_txns AS (
			SELECT *
			FROM transactions 
			WHERE %s = ? 
			AND timestamp >= ?::TIMESTAMP
		)
		SELECT CAST(
			CASE 
				WHEN COUNT(*) = 0 THEN 0
				ELSE %s 
			END AS DOUBLE
		) as metric_result
		FROM filtered_txns
	`, ac.Filter.Field, metricExpr)

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	stmt, err := db.PrepareContext(ctx, sqlStr)
	if err != nil {
		log.Error().Err(err).Str("sql", sqlStr).Msg("Failed to prepare aggregate query")
		return 0, fmt.Errorf("failed to prepare query: %w", err)
	}
	defer stmt.Close()

	var result float64
	err = stmt.QueryRowContext(ctx, filterVal, startTimeStr).Scan(&result)

	if err != nil {
		if err == sql.ErrNoRows {
			log.Debug().
				Str("metric", ac.Metric).
				Str("filter_field", ac.Filter.Field).
				Any("filter_val", filterVal).
				Msg("No rows found for aggregate query, returning 0")
			return 0, nil
		}

		log.Error().
			Err(err).
			Str("metric", ac.Metric).
			Str("filter_field", ac.Filter.Field).
			Any("filter_val", filterVal).
			Msg("Error executing aggregate query")
		return 0, fmt.Errorf("query error: %w", err)
	}

	return result, nil
}

func evalTimeFunction(tx map[string]any, c TimeFunctionCond) (bool, error) {
	got, ok := dig(tx, c.Field)
	if !ok {
		return false, nil
	}

	var ts time.Time
	switch v := got.(type) {
	case time.Time:
		ts = v
	case string:
		var err error
		ts, err = time.Parse(time.RFC3339, v)
		if err != nil {
			return false, fmt.Errorf("invalid timestamp format: %w", err)
		}
	default:
		return false, fmt.Errorf("field %s is not a timestamp", c.Field)
	}

	var result int
	switch c.Function {
	case "hour_of_day":
		result = ts.Hour()
	case "day_of_week":
		result = int(ts.Weekday())
	case "day_of_month":
		result = ts.Day()
	case "day_of_year":
		result = ts.YearDay()
	case "month_of_year":
		result = int(ts.Month())
	case "week_of_year":
		_, result = ts.ISOWeek()
	case "year":
		result = ts.Year()
	default:
		return false, fmt.Errorf("unsupported time function: %s", c.Function)
	}

	// day_of_week with "in" and list of day names (e.g. "Saturday", "Sunday")
	if c.Function == "day_of_week" && c.Op == "in" {
		if values, ok := c.Value.([]interface{}); ok && len(values) > 0 {
			if _, isStr := values[0].(string); isStr {
				for _, v := range values {
					if dayStr, ok := v.(string); ok {
						if strings.EqualFold(dayStr, ts.Weekday().String()) {
							return true, nil
						}
					}
				}
				return false, nil
			}
		}
	}

	// in / not_in with numeric (or other) lists, e.g. day_of_week(timestamp) in (0, 6)
	if c.Op == "in" || c.Op == "not_in" {
		return compareList(float64(result), c.Op, c.Value)
	}

	return compareScalar(float64(result), c.Op, c.Value)
}

// transactionsTableColumns are the columns that exist on the transactions table.
// previous_transaction match keys that are not in this set are interpreted as
// paths into the metadata JSON (meta_data.field or metadata.field).
var transactionsTableColumns = map[string]bool{
	"transaction_id": true, "amount": true, "currency": true,
	"source": true, "destination": true, "timestamp": true,
	"description": true, "metadata": true,
}

const metadataColumnPrefixMetaData = "meta_data."
const metadataColumnPrefixMetadata = "metadata."

func evalPreviousTransaction(tx map[string]any, pc PreviousTransactionCond) (bool, error) {
	db, err := getDB()
	if err != nil {
		return false, fmt.Errorf("failed to get database connection: %w", err)
	}

	dur, err := parseISODuration(pc.TimeWindow)
	if err != nil {
		return false, err
	}

	// Use the current transaction's timestamp as the window end (not time.Now()), so that
	// "previous within PT1H" means "in the 1h before this transaction", and works with
	// injected test data that has past timestamps.
	refTime, err := getTransactionTime(tx)
	if err != nil {
		return false, err
	}
	start := refTime.Add(-dur)

	var conditions []string
	var args []interface{}

	for field, value := range pc.Match {
		var cond string
		var arg interface{}

		if strValue, ok := value.(string); ok && strings.HasPrefix(strValue, "$current.") {
			fieldPath := strings.TrimPrefix(strValue, "$current.")
			currentValue, exists := dig(tx, fieldPath)
			if !exists {
				continue
			}
			arg = currentValue
			if transactionsTableColumns[field] {
				cond = field + " = ?"
			} else if strings.HasPrefix(field, metadataColumnPrefixMetaData) || strings.HasPrefix(field, metadataColumnPrefixMetadata) {
				jsonPath := "$." + strings.TrimPrefix(strings.TrimPrefix(field, metadataColumnPrefixMetaData), metadataColumnPrefixMetadata)
				cond = fmt.Sprintf("json_extract_string(metadata, %s) = ?", quoteSQLString(jsonPath))
			} else {
				continue
			}
		} else {
			arg = value
			if transactionsTableColumns[field] {
				cond = field + " = ?"
			} else if strings.HasPrefix(field, metadataColumnPrefixMetaData) || strings.HasPrefix(field, metadataColumnPrefixMetadata) {
				jsonPath := "$." + strings.TrimPrefix(strings.TrimPrefix(field, metadataColumnPrefixMetaData), metadataColumnPrefixMetadata)
				cond = fmt.Sprintf("json_extract_string(metadata, %s) = ?", quoteSQLString(jsonPath))
			} else {
				continue
			}
		}
		conditions = append(conditions, cond)
		args = append(args, arg)
	}

	conditions = append(conditions, "timestamp >= ? AND timestamp < ?")
	args = append(args, start.UTC(), refTime.UTC())

	query := fmt.Sprintf(`
		SELECT COUNT(*) 
		FROM transactions 
		WHERE %s
		LIMIT 1
	`, strings.Join(conditions, " AND "))

	var count int
	err = db.QueryRow(query, args...).Scan(&count)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// getTransactionTime returns the current transaction's timestamp from the map (created_at).
func getTransactionTime(tx map[string]any) (time.Time, error) {
	got, ok := dig(tx, "created_at")
	if !ok {
		return time.Time{}, fmt.Errorf("transaction has no created_at for previous_transaction window")
	}
	switch v := got.(type) {
	case time.Time:
		return v, nil
	case string:
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return time.Time{}, fmt.Errorf("created_at not RFC3339: %w", err)
		}
		return t, nil
	default:
		return time.Time{}, fmt.Errorf("created_at is not a time or string, got %T", got)
	}
}

// quoteSQLString returns a single-quoted string safe for use in SQL (escapes single quotes).
func quoteSQLString(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func evalLogical(tx map[string]any, lc LogicalCond, agg map[string]float64) (bool, error) {
	leftResult, err := evalCondition(tx, lc.Left, agg)
	if err != nil {
		return false, fmt.Errorf("failed to evaluate left condition: %w", err)
	}

	if lc.Operator == "or" && leftResult {
		return true, nil
	}

	if lc.Operator == "and" && !leftResult {
		return false, nil
	}

	rightResult, err := evalCondition(tx, lc.Right, agg)
	if err != nil {
		return false, fmt.Errorf("failed to evaluate right condition: %w", err)
	}

	switch lc.Operator {
	case "and":
		return leftResult && rightResult, nil
	case "or":
		return leftResult || rightResult, nil
	default:
		return false, fmt.Errorf("unsupported logical operator: %s", lc.Operator)
	}
}

func evalCondition(tx map[string]any, condition interface{}, agg map[string]float64) (bool, error) {
	condBytes, err := json.Marshal(condition)
	if err != nil {
		return false, fmt.Errorf("failed to marshal condition: %w", err)
	}

	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(condBytes, &probe); err != nil {
		return false, fmt.Errorf("failed to probe condition type: %w", err)
	}

	switch probe.Type {
	case "aggregate":
		var ac AggregateCond
		if err := json.Unmarshal(condBytes, &ac); err != nil {
			return false, err
		}
		return evalAggregate(tx, ac, agg)
	case "time_function":
		var tc TimeFunctionCond
		if err := json.Unmarshal(condBytes, &tc); err != nil {
			return false, err
		}
		return evalTimeFunction(tx, tc)
	case "previous_transaction":
		var pc PreviousTransactionCond
		if err := json.Unmarshal(condBytes, &pc); err != nil {
			return false, err
		}
		return evalPreviousTransaction(tx, pc)
	case "logical":
		var lc LogicalCond
		if err := json.Unmarshal(condBytes, &lc); err != nil {
			return false, err
		}
		return evalLogical(tx, lc, agg)
	default:
		var sc SimpleCond
		if err := json.Unmarshal(condBytes, &sc); err != nil {
			return false, err
		}
		return evalSimple(tx, sc)
	}
}

// dig resolves dot‑separated paths like "metadata.mcc".
func dig(m map[string]any, path string) (any, bool) {
	cur := any(m)
	for _, p := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = mm[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func toFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(t, 64)
		return f, err == nil
	default:
		return 0, false
	}
}

func resolvePlaceholder(val any, txn map[string]any) (any, bool) {
	s, ok := val.(string)
	if !ok || !strings.HasPrefix(s, "$current.") {
		return val, true // literal value unchanged
	}
	field := strings.TrimPrefix(s, "$current.")
	v, found := dig(txn, field)
	return v, found
}

func aggKey(ac AggregateCond, filterVal string) string {
	return fmt.Sprintf("%s|%s|%s|%s", ac.Metric, ac.TimeWindow, ac.Filter.Field, filterVal)
}

func parseISODuration(iso string) (time.Duration, error) {
	if strings.HasPrefix(iso, "PT") {
		iso = strings.TrimPrefix(iso, "PT")
		if strings.HasSuffix(iso, "H") {
			n, _ := strconv.Atoi(strings.TrimSuffix(iso, "H"))
			return time.Duration(n) * time.Hour, nil
		}
		if strings.HasSuffix(iso, "M") {
			n, _ := strconv.Atoi(strings.TrimSuffix(iso, "M"))
			return time.Duration(n) * time.Minute, nil
		}
		if strings.HasSuffix(iso, "S") {
			n, _ := strconv.Atoi(strings.TrimSuffix(iso, "S"))
			return time.Duration(n) * time.Second, nil
		}
	}
	if strings.HasPrefix(iso, "P") && strings.HasSuffix(iso, "D") {
		n, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(iso, "P"), "D"))
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return 0, fmt.Errorf("unsupported duration format: %s", iso)
}
