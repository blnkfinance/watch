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
	"testing"
	"time"
)

func TestDig(t *testing.T) {
	m := map[string]any{
		"amount": 100.0,
		"meta_data": map[string]any{
			"mcc":  "7995",
			"nest": map[string]any{"deep": "value"},
		},
	}

	tests := []struct {
		path   string
		want   any
		wantOK bool
	}{
		{"amount", 100.0, true},
		{"meta_data.mcc", "7995", true},
		{"meta_data.nest.deep", "value", true},
		{"missing", nil, false},
		{"meta_data.missing", nil, false},
		{"amount.sub", nil, false}, // non-map intermediate
	}

	for _, tt := range tests {
		got, ok := dig(m, tt.path)
		if ok != tt.wantOK || (ok && got != tt.want) {
			t.Errorf("dig(%q) = (%v, %v), want (%v, %v)", tt.path, got, ok, tt.want, tt.wantOK)
		}
	}
}

func TestToFloat(t *testing.T) {
	tests := []struct {
		in     any
		want   float64
		wantOK bool
	}{
		{float64(1.5), 1.5, true},
		{int(3), 3, true},
		{json.Number("2.5"), 2.5, true},
		{json.Number("abc"), 0, false},
		{"4.25", 4.25, true},
		{"not-a-number", 0, false},
		{true, 0, false},
		{nil, 0, false},
	}
	for _, tt := range tests {
		got, ok := toFloat(tt.in)
		if ok != tt.wantOK || (ok && got != tt.want) {
			t.Errorf("toFloat(%v) = (%v, %v), want (%v, %v)", tt.in, got, ok, tt.want, tt.wantOK)
		}
	}
}

func TestResolvePlaceholder(t *testing.T) {
	txn := map[string]any{"source": "acct-1", "meta_data": map[string]any{"mcc": "7995"}}

	if v, ok := resolvePlaceholder("literal", txn); !ok || v != "literal" {
		t.Errorf("literal string should pass through, got (%v, %v)", v, ok)
	}
	if v, ok := resolvePlaceholder(42, txn); !ok || v != 42 {
		t.Errorf("non-string should pass through, got (%v, %v)", v, ok)
	}
	if v, ok := resolvePlaceholder("$current.source", txn); !ok || v != "acct-1" {
		t.Errorf("$current.source = (%v, %v), want (acct-1, true)", v, ok)
	}
	if v, ok := resolvePlaceholder("$current.meta_data.mcc", txn); !ok || v != "7995" {
		t.Errorf("$current.meta_data.mcc = (%v, %v), want (7995, true)", v, ok)
	}
	if _, ok := resolvePlaceholder("$current.missing", txn); ok {
		t.Error("unresolvable placeholder should return ok=false")
	}
}

func TestCompareScalar(t *testing.T) {
	tests := []struct {
		got  any
		op   string
		want any
		res  bool
	}{
		{100.0, "eq", 100.0, true},
		{100.0, "ne", 99.0, true},
		{100.0, "gt", 50.0, true},
		{100.0, "gte", 100.0, true},
		{100.0, "lt", 200.0, true},
		{100.0, "lte", 100.0, true},
		{50.0, "gt", 100.0, false},
		// numeric coercion from strings
		{"100", "eq", 100.0, true},
		{"100", "gt", "50", true},
		// string fallback
		{"USD", "eq", "USD", true},
		{"USD", "ne", "NGN", true},
		{"USD", "gt", "NGN", false}, // non-numeric ordering unsupported -> false
	}
	for _, tt := range tests {
		res, err := compareScalar(tt.got, tt.op, tt.want)
		if err != nil {
			t.Errorf("compareScalar(%v %s %v) error: %v", tt.got, tt.op, tt.want, err)
			continue
		}
		if res != tt.res {
			t.Errorf("compareScalar(%v %s %v) = %v, want %v", tt.got, tt.op, tt.want, res, tt.res)
		}
	}
}

func TestCompareList(t *testing.T) {
	list := []any{"USD", "NGN", 5.0}

	if res, err := compareList("USD", "in", list); err != nil || !res {
		t.Errorf("USD in list = (%v, %v), want true", res, err)
	}
	if res, err := compareList("EUR", "in", list); err != nil || res {
		t.Errorf("EUR in list = (%v, %v), want false", res, err)
	}
	if res, err := compareList("EUR", "not_in", list); err != nil || !res {
		t.Errorf("EUR not_in list = (%v, %v), want true", res, err)
	}
	if res, err := compareList(5, "in", list); err != nil || !res {
		t.Errorf("5 in list = (%v, %v), want true (string compare)", res, err)
	}
	if _, err := compareList("x", "in", "not-a-list"); err == nil {
		t.Error("non-array value should error")
	}
}

func TestCompareRegex(t *testing.T) {
	if res, err := compareRegex("acct-123", "regex", "^acct-"); err != nil || !res {
		t.Errorf("regex match = (%v, %v), want true", res, err)
	}
	if res, err := compareRegex("other", "not_regex", "^acct-"); err != nil || !res {
		t.Errorf("not_regex = (%v, %v), want true", res, err)
	}
	if _, err := compareRegex("x", "regex", 123); err == nil {
		t.Error("non-string pattern should error")
	}
	if _, err := compareRegex("x", "regex", "["); err == nil {
		t.Error("invalid regex should error")
	}
}

func TestEvalSimple(t *testing.T) {
	txn := map[string]any{
		"amount":   1500.0,
		"currency": "USD",
		"source":   "acct-1",
		"meta_data": map[string]any{
			"country": "NG",
		},
	}

	tests := []struct {
		name string
		cond SimpleCond
		want bool
	}{
		{"gt passes", SimpleCond{Field: "amount", Op: "gt", Value: 1000.0}, true},
		{"gt fails", SimpleCond{Field: "amount", Op: "gt", Value: 2000.0}, false},
		{"eq string", SimpleCond{Field: "currency", Op: "eq", Value: "USD"}, true},
		{"in list", SimpleCond{Field: "currency", Op: "in", Value: []any{"USD", "EUR"}}, true},
		{"regex", SimpleCond{Field: "source", Op: "regex", Value: "^acct"}, true},
		{"nested field", SimpleCond{Field: "meta_data.country", Op: "eq", Value: "NG"}, true},
		{"missing field", SimpleCond{Field: "nope", Op: "eq", Value: 1}, false},
		{"placeholder value", SimpleCond{Field: "currency", Op: "eq", Value: "$current.currency"}, true},
		{"unresolvable placeholder", SimpleCond{Field: "currency", Op: "eq", Value: "$current.nope"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evalSimple(txn, tt.cond)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}

	if _, err := evalSimple(txn, SimpleCond{Field: "amount", Op: "bogus", Value: 1}); err == nil {
		t.Error("unsupported op should error")
	}
}

func TestEvalTimeFunction(t *testing.T) {
	// 2026-06-27 was a Saturday; 14:30 UTC.
	txn := map[string]any{
		"created_at": "2026-06-27T14:30:00Z",
		"ts_native":  time.Date(2026, 6, 27, 14, 30, 0, 0, time.UTC),
	}

	tests := []struct {
		name string
		cond TimeFunctionCond
		want bool
	}{
		{"hour_of_day eq", TimeFunctionCond{Function: "hour_of_day", Field: "created_at", Op: "eq", Value: 14.0}, true},
		{"hour_of_day gt", TimeFunctionCond{Function: "hour_of_day", Field: "created_at", Op: "gt", Value: 20.0}, false},
		{"day_of_week numeric (Saturday=6)", TimeFunctionCond{Function: "day_of_week", Field: "created_at", Op: "eq", Value: 6.0}, true},
		{"day_of_week name list", TimeFunctionCond{Function: "day_of_week", Field: "created_at", Op: "in", Value: []interface{}{"Saturday", "Sunday"}}, true},
		{"day_of_week name list no match", TimeFunctionCond{Function: "day_of_week", Field: "created_at", Op: "in", Value: []interface{}{"Monday"}}, false},
		{"day_of_week numeric list", TimeFunctionCond{Function: "day_of_week", Field: "created_at", Op: "in", Value: []interface{}{0.0, 6.0}}, true},
		{"day_of_week not_in", TimeFunctionCond{Function: "day_of_week", Field: "created_at", Op: "not_in", Value: []interface{}{1.0, 2.0}}, true},
		{"day_of_month", TimeFunctionCond{Function: "day_of_month", Field: "created_at", Op: "eq", Value: 27.0}, true},
		{"month_of_year", TimeFunctionCond{Function: "month_of_year", Field: "created_at", Op: "eq", Value: 6.0}, true},
		{"year", TimeFunctionCond{Function: "year", Field: "created_at", Op: "eq", Value: 2026.0}, true},
		{"day_of_year", TimeFunctionCond{Function: "day_of_year", Field: "created_at", Op: "eq", Value: 178.0}, true},
		{"week_of_year", TimeFunctionCond{Function: "week_of_year", Field: "created_at", Op: "eq", Value: 26.0}, true},
		{"native time.Time field", TimeFunctionCond{Function: "hour_of_day", Field: "ts_native", Op: "eq", Value: 14.0}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evalTimeFunction(txn, tt.cond)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("missing field", func(t *testing.T) {
		got, err := evalTimeFunction(txn, TimeFunctionCond{Function: "hour_of_day", Field: "nope", Op: "eq", Value: 1.0})
		if err != nil || got {
			t.Errorf("missing field should be (false, nil), got (%v, %v)", got, err)
		}
	})
	t.Run("bad timestamp string", func(t *testing.T) {
		badTxn := map[string]any{"created_at": "not-a-time"}
		if _, err := evalTimeFunction(badTxn, TimeFunctionCond{Function: "hour_of_day", Field: "created_at", Op: "eq", Value: 1.0}); err == nil {
			t.Error("invalid timestamp should error")
		}
	})
	t.Run("non-timestamp field", func(t *testing.T) {
		badTxn := map[string]any{"created_at": 12345}
		if _, err := evalTimeFunction(badTxn, TimeFunctionCond{Function: "hour_of_day", Field: "created_at", Op: "eq", Value: 1.0}); err == nil {
			t.Error("non-timestamp field should error")
		}
	})
	t.Run("unsupported function", func(t *testing.T) {
		if _, err := evalTimeFunction(txn, TimeFunctionCond{Function: "minute_of_hour", Field: "created_at", Op: "eq", Value: 1.0}); err == nil {
			t.Error("unsupported time function should error")
		}
	})
}

func TestGetTransactionTime(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	if got, err := getTransactionTime(map[string]any{"created_at": now}); err != nil || !got.Equal(now) {
		t.Errorf("time.Time created_at = (%v, %v)", got, err)
	}
	if got, err := getTransactionTime(map[string]any{"created_at": "2026-01-02T03:04:05Z"}); err != nil || !got.Equal(now) {
		t.Errorf("string created_at = (%v, %v)", got, err)
	}
	if _, err := getTransactionTime(map[string]any{}); err == nil {
		t.Error("missing created_at should error")
	}
	if _, err := getTransactionTime(map[string]any{"created_at": "bogus"}); err == nil {
		t.Error("non-RFC3339 created_at should error")
	}
	if _, err := getTransactionTime(map[string]any{"created_at": 42}); err == nil {
		t.Error("numeric created_at should error")
	}
}

func TestQuoteSQLString(t *testing.T) {
	if got := quoteSQLString("$.mcc"); got != "'$.mcc'" {
		t.Errorf("got %q", got)
	}
	if got := quoteSQLString("o'brien"); got != "'o''brien'" {
		t.Errorf("single quote not escaped: %q", got)
	}
}

func TestParseISODuration(t *testing.T) {
	tests := []struct {
		in   string
		want time.Duration
	}{
		{"PT1H", time.Hour},
		{"PT24H", 24 * time.Hour},
		{"PT30M", 30 * time.Minute},
		{"PT45S", 45 * time.Second},
		{"P7D", 7 * 24 * time.Hour},
	}
	for _, tt := range tests {
		got, err := parseISODuration(tt.in)
		if err != nil {
			t.Errorf("parseISODuration(%q) error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseISODuration(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}

	for _, bad := range []string{"1h", "PT1X", "P1M", "", "PTxH"} {
		if _, err := parseISODuration(bad); err == nil {
			t.Errorf("parseISODuration(%q) should error", bad)
		}
	}
}

func TestAggKey(t *testing.T) {
	ac := AggregateCond{Metric: "sum", TimeWindow: "PT1H", Filter: SimpleCond{Field: "source"}}
	if got := aggKey(ac, "acct-1"); got != "sum|PT1H|source|acct-1" {
		t.Errorf("aggKey = %q", got)
	}
}

func TestEvalLogical(t *testing.T) {
	txn := map[string]any{"amount": 1500.0, "currency": "USD"}

	amountGt := map[string]any{"field": "amount", "op": "gt", "value": 1000.0}
	amountLt := map[string]any{"field": "amount", "op": "lt", "value": 1000.0}
	currencyUSD := map[string]any{"field": "currency", "op": "eq", "value": "USD"}

	tests := []struct {
		name string
		lc   LogicalCond
		want bool
	}{
		{"and both true", LogicalCond{Operator: "and", Left: amountGt, Right: currencyUSD}, true},
		{"and left false short-circuits", LogicalCond{Operator: "and", Left: amountLt, Right: currencyUSD}, false},
		{"or left true short-circuits", LogicalCond{Operator: "or", Left: amountGt, Right: amountLt}, true},
		{"or both false", LogicalCond{Operator: "or", Left: amountLt, Right: map[string]any{"field": "currency", "op": "eq", "value": "EUR"}}, false},
		{"nested logical", LogicalCond{
			Operator: "and",
			Left:     amountGt,
			Right:    map[string]any{"type": "logical", "operator": "or", "left": amountLt, "right": currencyUSD},
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evalLogical(txn, tt.lc, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}

	if _, err := evalLogical(txn, LogicalCond{Operator: "xor", Left: amountGt, Right: currencyUSD}, nil); err == nil {
		t.Error("unsupported operator should error")
	}
}

func TestEvalCondition_TimeFunctionAndAggregate(t *testing.T) {
	txn := map[string]any{
		"created_at": "2026-06-27T14:30:00Z", // Saturday
		"source":     "acct-1",
	}

	tf := map[string]any{"type": "time_function", "function": "day_of_week", "field": "created_at", "op": "eq", "value": 6.0}
	got, err := evalCondition(txn, tf, nil)
	if err != nil || !got {
		t.Errorf("time_function condition = (%v, %v), want true", got, err)
	}

	agg := map[string]any{
		"type": "aggregate", "metric": "count", "time_window": "PT1H",
		"op": "gt", "value": 2.0,
		"filter": map[string]any{"field": "source", "op": "eq", "value": "$current.source"},
	}
	aggCtx := map[string]float64{"count|PT1H|source|acct-1": 5}
	got, err = evalCondition(txn, agg, aggCtx)
	if err != nil || !got {
		t.Errorf("aggregate condition = (%v, %v), want true", got, err)
	}
}

func TestEvalAggregate(t *testing.T) {
	txn := map[string]any{"source": "acct-1"}
	ac := AggregateCond{
		Metric: "sum", TimeWindow: "PT1H", Op: "gt", Value: 100,
		Filter: SimpleCond{Field: "source", Op: "eq", Value: "$current.source"},
	}

	got, err := evalAggregate(txn, ac, map[string]float64{"sum|PT1H|source|acct-1": 500})
	if err != nil || !got {
		t.Errorf("evalAggregate = (%v, %v), want true", got, err)
	}

	got, err = evalAggregate(txn, ac, map[string]float64{"sum|PT1H|source|acct-1": 50})
	if err != nil || got {
		t.Errorf("evalAggregate below threshold = (%v, %v), want false", got, err)
	}

	// unresolvable placeholder -> false, no error
	acBad := ac
	acBad.Filter.Value = "$current.missing"
	got, err = evalAggregate(txn, acBad, map[string]float64{})
	if err != nil || got {
		t.Errorf("unresolvable filter = (%v, %v), want (false, nil)", got, err)
	}

	// resolved placeholder but missing agg value -> internal error
	if _, err = evalAggregate(txn, ac, map[string]float64{}); err == nil {
		t.Error("missing aggregate key should error")
	}
}

func TestRuleAppliesAndEvaluateRules(t *testing.T) {
	txn := map[string]any{"amount": 1500.0, "currency": "USD"}

	mustRaw := func(v any) json.RawMessage {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return b
	}

	matching := Rule{
		ID:   1,
		Name: "high-amount-usd",
		When: []json.RawMessage{
			mustRaw(map[string]any{"field": "amount", "op": "gt", "value": 1000.0}),
			mustRaw(map[string]any{"field": "currency", "op": "eq", "value": "USD"}),
		},
		Then: Action{Verdict: "review", Score: 0.8, Reason: "large USD txn"},
	}
	nonMatching := Rule{
		ID:   2,
		Name: "low-amount",
		When: []json.RawMessage{
			mustRaw(map[string]any{"field": "amount", "op": "lt", "value": 100.0}),
		},
		Then: Action{Verdict: "block", Score: 1.0, Reason: "small"},
	}
	erroring := Rule{
		ID:   3,
		Name: "bad-op",
		When: []json.RawMessage{
			mustRaw(map[string]any{"field": "amount", "op": "bogus", "value": 1.0}),
		},
		Then: Action{Verdict: "block", Score: 1.0, Reason: "never"},
	}

	verdicts, err := EvaluateRules(txn, []Rule{matching, nonMatching, erroring}, nil)
	if err != nil {
		t.Fatalf("EvaluateRules error: %v", err)
	}
	if len(verdicts) != 1 {
		t.Fatalf("expected 1 verdict, got %d: %+v", len(verdicts), verdicts)
	}
	v := verdicts[0]
	if v.RuleID != 1 || v.Verdict != "review" || v.Score != 0.8 || v.Name != "high-amount-usd" {
		t.Errorf("unexpected verdict: %+v", v)
	}
}

func TestRunAggregateQueryAndBuildAggContext(t *testing.T) {
	clearTransactions(t)

	now := time.Now().UTC()
	recent := now.Add(-10 * time.Minute).Format("2006-01-02 15:04:05")
	old := now.Add(-48 * time.Hour).Format("2006-01-02 15:04:05")

	insertTestTransaction(t, "agg-1", 100, "USD", "acct-agg", "dest", recent, "", "")
	insertTestTransaction(t, "agg-2", 300, "USD", "acct-agg", "dest", recent, "", "")
	insertTestTransaction(t, "agg-3", 999, "USD", "acct-agg", "dest", old, "", "")      // outside window
	insertTestTransaction(t, "agg-4", 555, "USD", "acct-other", "dest", recent, "", "") // other account

	db, err := getDB()
	if err != nil {
		t.Fatalf("getDB: %v", err)
	}

	ctx := context.Background()
	filter := SimpleCond{Field: "source", Op: "eq", Value: "$current.source"}
	txn := map[string]any{"source": "acct-agg"}

	tests := []struct {
		metric string
		want   float64
	}{
		{"count", 2},
		{"sum", 400},
		{"avg", 200},
		{"max", 300},
		{"min", 100},
	}
	for _, tt := range tests {
		ac := AggregateCond{Metric: tt.metric, TimeWindow: "PT1H", Op: "gt", Value: 0, Filter: filter}
		got, err := runAggregateQuery(ctx, db, txn, ac)
		if err != nil {
			t.Errorf("runAggregateQuery(%s) error: %v", tt.metric, err)
			continue
		}
		if got != tt.want {
			t.Errorf("runAggregateQuery(%s) = %v, want %v", tt.metric, got, tt.want)
		}
	}

	// unsupported metric
	if _, err := runAggregateQuery(ctx, db, txn, AggregateCond{Metric: "median", TimeWindow: "PT1H", Filter: filter}); err == nil {
		t.Error("unsupported metric should error")
	}
	// invalid window
	if _, err := runAggregateQuery(ctx, db, txn, AggregateCond{Metric: "count", TimeWindow: "1h", Filter: filter}); err == nil {
		t.Error("invalid time window should error")
	}
	// unresolvable placeholder -> 0, nil
	acBad := AggregateCond{Metric: "count", TimeWindow: "PT1H", Filter: SimpleCond{Field: "source", Op: "eq", Value: "$current.missing"}}
	if got, err := runAggregateQuery(ctx, db, txn, acBad); err != nil || got != 0 {
		t.Errorf("unresolvable filter = (%v, %v), want (0, nil)", got, err)
	}

	// BuildAggContext end-to-end
	raw, _ := json.Marshal(map[string]any{
		"type": "aggregate", "metric": "sum", "time_window": "PT1H",
		"op": "gt", "value": 100.0,
		"filter": map[string]any{"field": "source", "op": "eq", "value": "$current.source"},
	})
	rules := []Rule{{ID: 1, Name: "agg-rule", When: []json.RawMessage{raw}, Then: Action{Verdict: "review", Score: 0.5}}}

	aggCtx, err := BuildAggContext(ctx, db, txn, rules)
	if err != nil {
		t.Fatalf("BuildAggContext error: %v", err)
	}
	if got := aggCtx["sum|PT1H|source|acct-agg"]; got != 400 {
		t.Errorf("aggContext sum = %v, want 400", got)
	}

	// Full evaluation of the aggregate rule
	verdicts, err := EvaluateRules(txn, rules, aggCtx)
	if err != nil {
		t.Fatalf("EvaluateRules error: %v", err)
	}
	if len(verdicts) != 1 {
		t.Fatalf("expected aggregate rule to fire, got %+v", verdicts)
	}
}

func TestEvalPreviousTransaction(t *testing.T) {
	clearTransactions(t)

	ref := time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)
	prev := ref.Add(-30 * time.Minute).Format("2006-01-02 15:04:05")
	tooOld := ref.Add(-3 * time.Hour).Format("2006-01-02 15:04:05")

	insertTestTransaction(t, "prev-1", 100, "USD", "acct-p", "dest-x", prev, "", `{"mcc": "7995"}`)
	insertTestTransaction(t, "prev-2", 100, "USD", "acct-p", "dest-y", tooOld, "", "")

	txn := map[string]any{
		"source":     "acct-p",
		"created_at": ref.Format(time.RFC3339),
		"meta_data":  map[string]any{"mcc": "7995"},
	}

	t.Run("match on column via $current", func(t *testing.T) {
		pc := PreviousTransactionCond{TimeWindow: "PT1H", Match: map[string]any{"source": "$current.source"}}
		got, err := evalPreviousTransaction(txn, pc)
		if err != nil || !got {
			t.Errorf("got (%v, %v), want true", got, err)
		}
	})

	t.Run("match on literal column value", func(t *testing.T) {
		pc := PreviousTransactionCond{TimeWindow: "PT1H", Match: map[string]any{"destination": "dest-x"}}
		got, err := evalPreviousTransaction(txn, pc)
		if err != nil || !got {
			t.Errorf("got (%v, %v), want true", got, err)
		}
	})

	t.Run("outside window", func(t *testing.T) {
		pc := PreviousTransactionCond{TimeWindow: "PT1H", Match: map[string]any{"destination": "dest-y"}}
		got, err := evalPreviousTransaction(txn, pc)
		if err != nil || got {
			t.Errorf("got (%v, %v), want false", got, err)
		}
	})

	t.Run("metadata match", func(t *testing.T) {
		pc := PreviousTransactionCond{TimeWindow: "PT1H", Match: map[string]any{"meta_data.mcc": "$current.meta_data.mcc"}}
		got, err := evalPreviousTransaction(txn, pc)
		if err != nil || !got {
			t.Errorf("got (%v, %v), want true", got, err)
		}
	})

	t.Run("no match", func(t *testing.T) {
		pc := PreviousTransactionCond{TimeWindow: "PT1H", Match: map[string]any{"source": "acct-nope"}}
		got, err := evalPreviousTransaction(txn, pc)
		if err != nil || got {
			t.Errorf("got (%v, %v), want false", got, err)
		}
	})

	t.Run("invalid window", func(t *testing.T) {
		pc := PreviousTransactionCond{TimeWindow: "1h", Match: map[string]any{"source": "acct-p"}}
		if _, err := evalPreviousTransaction(txn, pc); err == nil {
			t.Error("invalid window should error")
		}
	})

	t.Run("missing created_at", func(t *testing.T) {
		pc := PreviousTransactionCond{TimeWindow: "PT1H", Match: map[string]any{"source": "acct-p"}}
		if _, err := evalPreviousTransaction(map[string]any{"source": "acct-p"}, pc); err == nil {
			t.Error("missing created_at should error")
		}
	})
}
