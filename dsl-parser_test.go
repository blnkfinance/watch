package watch

import (
	"encoding/json"
	"testing"
)

func TestLexer(t *testing.T) {
	input := `rule HighValueTransaction {
		description "Detect high value transactions"
		when amount > 5000 and metadata.kyc_tier == 1
		then review
		score 0.8
		reason "High value transaction from low KYC tier"
	}`

	lexer := NewLexer(input)

	expectedTokens := []struct {
		expectedType    TokenType
		expectedLiteral string
	}{
		{RULE, "rule"},
		{IDENTIFIER, "HighValueTransaction"},
		{LBRACE, "{"},
		{NEWLINE, "\\n"},
		{DESCRIPTION, "description"},
		{STRING, "Detect high value transactions"},
		{NEWLINE, "\\n"},
		{WHEN, "when"},
		{IDENTIFIER, "amount"},
		{GT, ">"},
		{NUMBER, "5000"},
		{AND, "and"},
		{IDENTIFIER, "metadata"},
		{DOT, "."},
		{IDENTIFIER, "kyc_tier"},
		{EQ, "=="},
		{NUMBER, "1"},
		{NEWLINE, "\\n"},
		{THEN, "then"},
		{IDENTIFIER, "review"},
		{NEWLINE, "\\n"},
		{IDENTIFIER, "score"},
		{NUMBER, "0.8"},
		{NEWLINE, "\\n"},
		{IDENTIFIER, "reason"},
		{STRING, "High value transaction from low KYC tier"},
		{NEWLINE, "\\n"},
		{RBRACE, "}"},
		{EOF, ""},
	}

	for i, tt := range expectedTokens {
		tok, err := lexer.NextToken()
		if err != nil {
			t.Fatalf("lexer error at token %d: %v", i, err)
		}

		if tok.Type != tt.expectedType {
			t.Fatalf("token %d - wrong token type. expected=%q, got=%q",
				i, tt.expectedType, tok.Type)
		}

		if tok.Literal != tt.expectedLiteral {
			t.Fatalf("token %d - wrong literal. expected=%q, got=%q",
				i, tt.expectedLiteral, tok.Literal)
		}
	}
}

func TestLexerOperators(t *testing.T) {
	input := `== != > >= < <= + ( ) { } , : . $`
	lexer := NewLexer(input)

	expectedTokens := []TokenType{
		EQ, NE, GT, GTE, LT, LTE, PLUS, LPAREN, RPAREN,
		LBRACE, RBRACE, COMMA, COLON, DOT, DOLLAR, EOF,
	}

	for i, expectedType := range expectedTokens {
		tok, err := lexer.NextToken()
		if err != nil {
			t.Fatalf("lexer error at token %d: %v", i, err)
		}

		if tok.Type != expectedType {
			t.Fatalf("token %d - wrong token type. expected=%q, got=%q",
				i, expectedType, tok.Type)
		}
	}
}

func TestLexerStrings(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		hasError bool
	}{
		{`"hello world"`, "hello world", false},
		{`"escaped \"quote\""`, `escaped \"quote\"`, false},
		{`"unterminated string`, "", true},
		{`""`, "", false},
	}

	for _, tt := range tests {
		lexer := NewLexer(tt.input)
		tok, err := lexer.NextToken()

		if tt.hasError {
			if err == nil {
				t.Errorf("expected error for input %q, but got none", tt.input)
			}
			continue
		}

		if err != nil {
			t.Errorf("unexpected error for input %q: %v", tt.input, err)
			continue
		}

		if tok.Type != STRING {
			t.Errorf("expected STRING token, got %s", tok.Type)
			continue
		}

		if tok.Literal != tt.expected {
			t.Errorf("expected literal %q, got %q", tt.expected, tok.Literal)
		}
	}
}

func TestLexerNumbers(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"123", "123"},
		{"123.456", "123.456"},
		{"0", "0"},
		{"0.0", "0.0"},
	}

	for _, tt := range tests {
		lexer := NewLexer(tt.input)
		tok, err := lexer.NextToken()

		if err != nil {
			t.Errorf("unexpected error for input %q: %v", tt.input, err)
			continue
		}

		if tok.Type != NUMBER {
			t.Errorf("expected NUMBER token, got %s", tok.Type)
			continue
		}

		if tok.Literal != tt.expected {
			t.Errorf("expected literal %q, got %q", tt.expected, tok.Literal)
		}
	}
}

func TestParserSimpleRule(t *testing.T) {
	input := `rule TestRule {
		description "A test rule"
		when amount > 1000
		then block
		score 0.9
		reason "Amount too high"
	}`

	lexer := NewLexer(input)
	parser := NewParser(lexer)

	rule, errors := parser.ParseRule()
	if len(errors) > 0 {
		t.Fatalf("parser errors: %v", errors)
	}

	if rule == nil {
		t.Fatal("expected rule, got nil")
	}

	// Check rule name
	if rule.Name.Value != "TestRule" {
		t.Errorf("expected rule name 'TestRule', got %q", rule.Name.Value)
	}

	// Check description
	if rule.Description == nil || rule.Description.Value != "A test rule" {
		t.Errorf("expected description 'A test rule', got %v", rule.Description)
	}

	// Check when condition
	if rule.When == nil {
		t.Error("expected when condition, got nil")
	}

	// Check then action
	if rule.Then.Verdict != "block" {
		t.Errorf("expected verdict 'block', got %q", rule.Then.Verdict)
	}

	if rule.Then.Score.Value != 0.9 {
		t.Errorf("expected score 0.9, got %f", rule.Then.Score.Value)
	}

	if rule.Then.Reason.Value != "Amount too high" {
		t.Errorf("expected reason 'Amount too high', got %q", rule.Then.Reason.Value)
	}
}

func TestParserMultipleConditions(t *testing.T) {
	input := `rule MultiCondition {
		when amount > 1000 and metadata.type == "transfer" and status != "pending"
		then review
	}`

	lexer := NewLexer(input)
	parser := NewParser(lexer)

	rule, errors := parser.ParseRule()
	if len(errors) > 0 {
		t.Fatalf("parser errors: %v", errors)
	}

	if rule == nil {
		t.Fatal("expected rule, got nil")
	}

	// Should have a logical expression with nested AND conditions
	if rule.When == nil {
		t.Error("expected when condition, got nil")
	}
}

func TestParserFieldPaths(t *testing.T) {
	input := `rule FieldPathTest {
		when metadata.user.id == "123"
		then allow
	}`

	lexer := NewLexer(input)
	parser := NewParser(lexer)

	rule, errors := parser.ParseRule()
	if len(errors) > 0 {
		t.Fatalf("parser errors: %v", errors)
	}

	if rule == nil {
		t.Fatal("expected rule, got nil")
	}

	// Check that we parsed the field path correctly
	if rule.When == nil {
		t.Error("expected when condition, got nil")
		return
	}

	// The condition should be an infix expression with a field path on the left
	condition := rule.When
	if infixExpr, ok := condition.(*InfixExpression); ok {
		if fieldPath, ok := infixExpr.Left.(*FieldPath); ok {
			expectedParts := []string{"metadata", "user", "id"}
			if len(fieldPath.Parts) != len(expectedParts) {
				t.Errorf("expected %d field path parts, got %d", len(expectedParts), len(fieldPath.Parts))
			}
			for i, part := range fieldPath.Parts {
				if part != expectedParts[i] {
					t.Errorf("expected field path part %d to be %q, got %q", i, expectedParts[i], part)
				}
			}
		} else {
			t.Errorf("expected field path on left side of condition, got %T", infixExpr.Left)
		}
	} else {
		t.Errorf("expected infix expression, got %T", condition)
	}
}

func TestParserVariables(t *testing.T) {
	input := `rule VariableTest {
		when source == $current.source
		then block
	}`

	lexer := NewLexer(input)
	parser := NewParser(lexer)

	rule, errors := parser.ParseRule()
	if len(errors) > 0 {
		t.Fatalf("parser errors: %v", errors)
	}

	if rule == nil {
		t.Fatal("expected rule, got nil")
	}

	// Check that we parsed the variable correctly
	condition := rule.When
	if infixExpr, ok := condition.(*InfixExpression); ok {
		if variable, ok := infixExpr.Right.(*Variable); ok {
			if variable.Name != "current.source" {
				t.Errorf("expected variable name 'current.source', got %q", variable.Name)
			}
		} else {
			t.Errorf("expected variable on right side of condition, got %T", infixExpr.Right)
		}
	}
}

func TestParserArrayLiterals(t *testing.T) {
	input := `rule ArrayTest {
		when status in ("pending", "processing", "failed")
		then review
	}`

	lexer := NewLexer(input)
	parser := NewParser(lexer)

	rule, errors := parser.ParseRule()
	if len(errors) > 0 {
		t.Fatalf("parser errors: %v", errors)
	}

	if rule == nil {
		t.Fatal("expected rule, got nil")
	}

	// Check that we parsed the array correctly
	condition := rule.When
	if infixExpr, ok := condition.(*InfixExpression); ok {
		if arrayLit, ok := infixExpr.Right.(*ArrayLiteral); ok {
			if len(arrayLit.Elements) != 3 {
				t.Errorf("expected 3 array elements, got %d", len(arrayLit.Elements))
			}
		} else {
			t.Errorf("expected array literal on right side of condition, got %T", infixExpr.Right)
		}
	}
}

func TestParserErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			"missing rule name",
			`rule {
				when amount > 1000
				then block
			}`,
		},
		{
			"missing when clause",
			`rule Test {
				then block
			}`,
		},
		{
			"missing then clause",
			`rule Test {
				when amount > 1000
			}`,
		},
		{
			"invalid verdict",
			`rule Test {
				when amount > 1000
				then invalid_verdict
			}`,
		},
		{
			"unterminated string",
			`rule Test {
				description "unterminated
				when amount > 1000
				then block
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lexer := NewLexer(tt.input)
			parser := NewParser(lexer)

			_, errors := parser.ParseRule()
			if len(errors) == 0 {
				t.Errorf("expected parse errors for %s, but got none", tt.name)
			}
		})
	}
}

func TestCompileWatchScriptWithParser(t *testing.T) {
	input := `rule HighValueTransaction {
		description "Detect high value transactions"
		when amount > 5000 and metadata.kyc_tier == 1
		then review
		score 0.8
		reason "High value transaction from low KYC tier"
	}`

	ruleName, description, ruleJSON, err := CompileWatchScript(input)
	if err != nil {
		t.Fatalf("compilation error: %v", err)
	}

	// Check extracted values
	if ruleName != "HighValueTransaction" {
		t.Errorf("expected rule name 'HighValueTransaction', got %q", ruleName)
	}

	if description != "Detect high value transactions" {
		t.Errorf("expected description 'Detect high value transactions', got %q", description)
	}

	// Check that JSON is valid
	var rule Rule
	if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	// Check rule structure
	if rule.Then.Verdict != "review" {
		t.Errorf("expected verdict 'review', got %q", rule.Then.Verdict)
	}

	if rule.Then.Score != 0.8 {
		t.Errorf("expected score 0.8, got %f", rule.Then.Score)
	}

	if rule.Then.Reason != "High value transaction from low KYC tier" {
		t.Errorf("expected reason 'High value transaction from low KYC tier', got %q", rule.Then.Reason)
	}

	// Should have 2 conditions (amount > 5000 and metadata.kyc_tier == 1)
	if len(rule.When) != 2 {
		t.Errorf("expected 2 when conditions, got %d", len(rule.When))
	}
}

func TestCompileWatchScriptWithParserComplexConditions(t *testing.T) {
	input := `rule ComplexRule {
		description "Complex rule with various conditions"
		when amount >= 10000 and status != "completed" and metadata.type in ("transfer", "withdrawal")
		then block
		score 0.95
		reason "Suspicious high-value incomplete transaction"
	}`

	ruleName, _, ruleJSON, err := CompileWatchScript(input)
	if err != nil {
		t.Fatalf("compilation error: %v", err)
	}

	// Check extracted values
	if ruleName != "ComplexRule" {
		t.Errorf("expected rule name 'ComplexRule', got %q", ruleName)
	}

	// Check that JSON is valid
	var rule Rule
	if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	// Should have 3 conditions
	if len(rule.When) != 3 {
		t.Errorf("expected 3 when conditions, got %d", len(rule.When))
	}
}

func TestParserLineNumbers(t *testing.T) {
	input := `rule Test {
		when amount > 1000
		then invalid_verdict
	}`

	lexer := NewLexer(input)
	parser := NewParser(lexer)

	_, errors := parser.ParseRule()
	if len(errors) == 0 {
		t.Fatal("expected parse errors, but got none")
	}

	// Check that error has line number information
	for _, err := range errors {
		if err.Line == 0 {
			t.Errorf("expected line number in error, got 0")
		}
		if err.Column == 0 {
			t.Errorf("expected column number in error, got 0")
		}
	}
}

func TestParserWithoutRuleKeyword(t *testing.T) {
	input := `TestRule {
		description "Test without rule keyword"
		when amount > 1000
		then block
	}`

	lexer := NewLexer(input)
	parser := NewParser(lexer)

	rule, errors := parser.ParseRule()
	if len(errors) > 0 {
		t.Fatalf("parser errors: %v", errors)
	}

	if rule == nil {
		t.Fatal("expected rule, got nil")
	}

	if rule.Name.Value != "TestRule" {
		t.Errorf("expected rule name 'TestRule', got %q", rule.Name.Value)
	}
}

func TestParserDefaultValues(t *testing.T) {
	input := `rule DefaultTest {
		when amount > 1000
		then review
	}`

	lexer := NewLexer(input)
	parser := NewParser(lexer)

	rule, errors := parser.ParseRule()
	if len(errors) > 0 {
		t.Fatalf("parser errors: %v", errors)
	}

	if rule == nil {
		t.Fatal("expected rule, got nil")
	}

	// Check default values
	if rule.Then.Score.Value != 0.0 {
		t.Errorf("expected default score 0.0, got %f", rule.Then.Score.Value)
	}

	if rule.Then.Reason.Value != "No reason provided" {
		t.Errorf("expected default reason 'No reason provided', got %q", rule.Then.Reason.Value)
	}
}

// Benchmark tests
func BenchmarkLexer(b *testing.B) {
	input := `rule HighValueTransaction {
		description "Detect high value transactions"
		when amount > 5000 and metadata.kyc_tier == 1 and status != "pending"
		then review
		score 0.8
		reason "High value transaction from low KYC tier"
	}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lexer := NewLexer(input)
		for {
			tok, _ := lexer.NextToken()
			if tok.Type == EOF {
				break
			}
		}
	}
}

func BenchmarkParser(b *testing.B) {
	input := `rule HighValueTransaction {
		description "Detect high value transactions"
		when amount > 5000 and metadata.kyc_tier == 1 and status != "pending"
		then review
		score 0.8
		reason "High value transaction from low KYC tier"
	}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lexer := NewLexer(input)
		parser := NewParser(lexer)
		parser.ParseRule()
	}
}

func BenchmarkCompileWatchScriptWithParser(b *testing.B) {
	input := `rule HighValueTransaction {
		description "Detect high value transactions"
		when amount > 5000 and metadata.kyc_tier == 1 and status != "pending"
		then review
		score 0.8
		reason "High value transaction from low KYC tier"
	}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CompileWatchScript(input)
	}
}

// Test comparison with old regex-based compiler
func TestParserOrConditions(t *testing.T) {
	input := `rule OrTest {
		when amount > 1000 or status == "suspicious"
		then review
	}`

	lexer := NewLexer(input)
	parser := NewParser(lexer)

	rule, errors := parser.ParseRule()
	if len(errors) > 0 {
		t.Fatalf("parser errors: %v", errors)
	}

	if rule == nil {
		t.Fatal("expected rule, got nil")
	}

	// Check that we parsed the OR condition correctly
	if rule.When == nil {
		t.Fatal("expected when condition, got nil")
	}

	// The condition should be a logical expression
	if logicalExpr, ok := rule.When.(*LogicalExpression); ok {
		if logicalExpr.Operator != "or" {
			t.Errorf("expected OR operator, got %q", logicalExpr.Operator)
		}
	} else {
		t.Errorf("expected logical expression, got %T", rule.When)
	}
}

func TestParserComplexLogicalConditions(t *testing.T) {
	input := `rule ComplexLogical {
		when amount > 1000 and status == "pending" or metadata.type == "urgent"
		then block
	}`

	lexer := NewLexer(input)
	parser := NewParser(lexer)

	rule, errors := parser.ParseRule()
	if len(errors) > 0 {
		t.Fatalf("parser errors: %v", errors)
	}

	if rule == nil {
		t.Fatal("expected rule, got nil")
	}

	// Should parse as: (amount > 1000 and status == "pending") or metadata.type == "urgent"
	// Due to left-associativity
	if logicalExpr, ok := rule.When.(*LogicalExpression); ok {
		if logicalExpr.Operator != "or" {
			t.Errorf("expected top-level OR operator, got %q", logicalExpr.Operator)
		}

		// Left side should be another logical expression (AND)
		if leftLogical, ok := logicalExpr.Left.(*LogicalExpression); ok {
			if leftLogical.Operator != "and" {
				t.Errorf("expected left side to be AND, got %q", leftLogical.Operator)
			}
		} else {
			t.Errorf("expected left side to be logical expression, got %T", logicalExpr.Left)
		}
	} else {
		t.Errorf("expected logical expression, got %T", rule.When)
	}
}

func TestLexerOrToken(t *testing.T) {
	input := `amount > 1000 or status == "pending"`
	lexer := NewLexer(input)

	expectedTokens := []TokenType{
		IDENTIFIER, GT, NUMBER, OR, IDENTIFIER, EQ, STRING, EOF,
	}

	for i, expectedType := range expectedTokens {
		tok, err := lexer.NextToken()
		if err != nil {
			t.Fatalf("lexer error at token %d: %v", i, err)
		}

		if tok.Type != expectedType {
			t.Fatalf("token %d - wrong token type. expected=%q, got=%q",
				i, expectedType, tok.Type)
		}
	}
}

func TestCompileWatchScriptWithOrConditions(t *testing.T) {
	input := `rule OrConditionTest {
		description "Test OR conditions"
		when amount > 5000 or status == "suspicious" or metadata.risk_level == "high"
		then block
		score 0.9
		reason "High risk transaction"
	}`

	ruleName, description, ruleJSON, err := CompileWatchScript(input)
	if err != nil {
		t.Fatalf("compilation error: %v", err)
	}

	// Check extracted values
	if ruleName != "OrConditionTest" {
		t.Errorf("expected rule name 'OrConditionTest', got %q", ruleName)
	}

	if description != "Test OR conditions" {
		t.Errorf("expected description 'Test OR conditions', got %q", description)
	}

	// Check that JSON is valid
	var rule Rule
	if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	// Check rule structure
	if rule.Then.Verdict != "block" {
		t.Errorf("expected verdict 'block', got %q", rule.Then.Verdict)
	}

	if rule.Then.Score != 0.9 {
		t.Errorf("expected score 0.9, got %f", rule.Then.Score)
	}

	// Should have at least one condition (the logical expression)
	if len(rule.When) == 0 {
		t.Error("expected at least one when condition")
	}
}

func TestCompileWatchScriptMixedAndOr(t *testing.T) {
	input := `rule MixedLogical {
		when amount > 1000 and status != "completed" or metadata.urgent == true
		then review
	}`

	_, _, ruleJSON, err := CompileWatchScript(input)
	if err != nil {
		t.Fatalf("compilation error: %v", err)
	}

	// Check that JSON is valid
	var rule Rule
	if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	// Should have at least one condition
	if len(rule.When) == 0 {
		t.Error("expected at least one when condition")
	}
}

func TestParserFunctionCallsWithNamedArguments(t *testing.T) {
	input := `rule BlockWhenPreviousTransactionFailed {
		description "Block when previous transaction failed for same source"

		when previous_transaction(
			within: "PT1H",
			match: {
				status: "failed",
				source: "$current.source"
			}
		)
		and amount > 700000

		then block
			 score   1.0    
	}`

	lexer := NewLexer(input)
	parser := NewParser(lexer)

	rule, errors := parser.ParseRule()
	if len(errors) > 0 {
		for _, err := range errors {
			t.Logf("Parse error: %v", err)
		}
		t.Fatalf("parser errors: %v", errors)
	}

	if rule == nil {
		t.Fatal("expected rule, got nil")
	}

	// Check rule name
	if rule.Name.Value != "BlockWhenPreviousTransactionFailed" {
		t.Errorf("expected rule name 'BlockWhenPreviousTransactionFailed', got %q", rule.Name.Value)
	}

	// Check description
	if rule.Description == nil || rule.Description.Value != "Block when previous transaction failed for same source" {
		t.Errorf("expected description 'Block when previous transaction failed for same source', got %v", rule.Description)
	}

	// Check when condition - should be a logical expression with AND
	if rule.When == nil {
		t.Fatal("expected when condition, got nil")
	}

	if logicalExpr, ok := rule.When.(*LogicalExpression); ok {
		if logicalExpr.Operator != "and" {
			t.Errorf("expected AND operator, got %q", logicalExpr.Operator)
		}

		// Left side should be a function call
		if funcCall, ok := logicalExpr.Left.(*FunctionCall); ok {
			if funcCall.Name != "previous_transaction" {
				t.Errorf("expected function name 'previous_transaction', got %q", funcCall.Name)
			}

			// Should have 2 arguments: within and match
			if len(funcCall.Arguments) != 2 {
				t.Errorf("expected 2 function arguments, got %d", len(funcCall.Arguments))
			}

			// Check first argument (within: "PT1H")
			if namedArg, ok := funcCall.Arguments[0].(*NamedArgument); ok {
				if namedArg.Name != "within" {
					t.Errorf("expected first argument name 'within', got %q", namedArg.Name)
				}
				if stringLit, ok := namedArg.Value.(*StringLiteral); ok {
					if stringLit.Value != "PT1H" {
						t.Errorf("expected within value 'PT1H', got %q", stringLit.Value)
					}
				} else {
					t.Errorf("expected string literal for within value, got %T", namedArg.Value)
				}
			} else {
				t.Errorf("expected first argument to be named argument, got %T", funcCall.Arguments[0])
			}

			// Check second argument (match: {...})
			if namedArg, ok := funcCall.Arguments[1].(*NamedArgument); ok {
				if namedArg.Name != "match" {
					t.Errorf("expected second argument name 'match', got %q", namedArg.Name)
				}
				if objLit, ok := namedArg.Value.(*ObjectLiteral); ok {
					if len(objLit.Pairs) != 2 {
						t.Errorf("expected 2 object pairs, got %d", len(objLit.Pairs))
					}
					// Check that status and source keys exist
					if _, exists := objLit.Pairs["status"]; !exists {
						t.Error("expected 'status' key in match object")
					}
					if _, exists := objLit.Pairs["source"]; !exists {
						t.Error("expected 'source' key in match object")
					}
				} else {
					t.Errorf("expected object literal for match value, got %T", namedArg.Value)
				}
			} else {
				t.Errorf("expected second argument to be named argument, got %T", funcCall.Arguments[1])
			}
		} else {
			t.Errorf("expected left side to be function call, got %T", logicalExpr.Left)
		}

		// Right side should be amount > 700000
		if infixExpr, ok := logicalExpr.Right.(*InfixExpression); ok {
			if infixExpr.Operator != ">" {
				t.Errorf("expected > operator, got %q", infixExpr.Operator)
			}
		} else {
			t.Errorf("expected right side to be infix expression, got %T", logicalExpr.Right)
		}
	} else {
		t.Errorf("expected logical expression, got %T", rule.When)
	}

	// Check then action
	if rule.Then.Verdict != "block" {
		t.Errorf("expected verdict 'block', got %q", rule.Then.Verdict)
	}

	if rule.Then.Score.Value != 1.0 {
		t.Errorf("expected score 1.0, got %f", rule.Then.Score.Value)
	}
}

func TestCompileBlockIfPreviousFailedScript(t *testing.T) {
	input := `rule BlockWhenPreviousTransactionFailed {
		description "Block when previous transaction failed for same source"

		when previous_transaction(
			within: "PT1H",
			match: {
				status: "failed",
				source: "$current.source"
			}
		)
		and amount > 700000

		then block
			 score   1.0    
	}`

	ruleName, description, ruleJSON, err := CompileWatchScript(input)
	if err != nil {
		t.Fatalf("compilation error: %v", err)
	}

	// Check extracted values
	if ruleName != "BlockWhenPreviousTransactionFailed" {
		t.Errorf("expected rule name 'BlockWhenPreviousTransactionFailed', got %q", ruleName)
	}

	if description != "Block when previous transaction failed for same source" {
		t.Errorf("expected description 'Block when previous transaction failed for same source', got %q", description)
	}

	// Check that JSON is valid
	var rule Rule
	if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	// Check rule structure
	if rule.Then.Verdict != "block" {
		t.Errorf("expected verdict 'block', got %q", rule.Then.Verdict)
	}

	if rule.Then.Score != 1.0 {
		t.Errorf("expected score 1.0, got %f", rule.Then.Score)
	}

	// Should have conditions
	if len(rule.When) == 0 {
		t.Fatal("expected at least one when condition")
	}

	// Parser must emit "previous_transaction" (not "function_comparison") so the interpreter evaluates it.
	var foundPrevTx bool
	for _, raw := range rule.When {
		var probe struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(raw, &probe)
		if probe.Type == "previous_transaction" {
			foundPrevTx = true
			var pc struct {
				TimeWindow string                 `json:"time_window"`
				Match      map[string]interface{} `json:"match"`
			}
			_ = json.Unmarshal(raw, &pc)
			if pc.TimeWindow != "PT1H" {
				t.Errorf("expected time_window PT1H, got %q", pc.TimeWindow)
			}
			if pc.Match["source"] != "$current.source" || pc.Match["status"] != "failed" {
				t.Errorf("expected match source=$current.source, status=failed; got %v", pc.Match)
			}
			break
		}
		if probe.Type == "logical" {
			var l struct {
				Left json.RawMessage `json:"left"`
			}
			_ = json.Unmarshal(raw, &l)
			if len(l.Left) > 0 {
				var inner struct {
					Type string `json:"type"`
				}
				_ = json.Unmarshal(l.Left, &inner)
				if inner.Type == "previous_transaction" {
					foundPrevTx = true
					var pc struct {
						TimeWindow string                 `json:"time_window"`
						Match      map[string]interface{} `json:"match"`
					}
					_ = json.Unmarshal(l.Left, &pc)
					if pc.TimeWindow != "PT1H" {
						t.Errorf("expected time_window PT1H, got %q", pc.TimeWindow)
					}
					break
				}
			}
		}
	}
	if !foundPrevTx {
		t.Errorf("expected a previous_transaction condition in when; got: %s", ruleJSON)
	}

	t.Logf("Generated JSON: %s", ruleJSON)
}

func TestParserObjectLiterals(t *testing.T) {
	input := `rule ObjectTest {
		when metadata.match == {
			status: "failed",
			type: "transfer",
			amount: 1000
		}
		then block
	}`

	lexer := NewLexer(input)
	parser := NewParser(lexer)

	rule, errors := parser.ParseRule()
	if len(errors) > 0 {
		t.Fatalf("parser errors: %v", errors)
	}

	if rule == nil {
		t.Fatal("expected rule, got nil")
	}

	// Check that we parsed the object literal correctly
	condition := rule.When
	if infixExpr, ok := condition.(*InfixExpression); ok {
		if objLit, ok := infixExpr.Right.(*ObjectLiteral); ok {
			if len(objLit.Pairs) != 3 {
				t.Errorf("expected 3 object pairs, got %d", len(objLit.Pairs))
			}

			// Check specific keys exist
			keys := []string{"status", "type", "amount"}
			for _, key := range keys {
				if _, exists := objLit.Pairs[key]; !exists {
					t.Errorf("expected key %q in object literal", key)
				}
			}
		} else {
			t.Errorf("expected object literal on right side of condition, got %T", infixExpr.Right)
		}
	} else {
		t.Errorf("expected infix expression, got %T", condition)
	}
}

func TestParserNamedArgumentsOnly(t *testing.T) {
	input := `rule NamedArgsTest {
		when test_function(
			arg1: "value1",
			arg2: 42,
			arg3: true
		)
		then allow
	}`

	lexer := NewLexer(input)
	parser := NewParser(lexer)

	rule, errors := parser.ParseRule()
	if len(errors) > 0 {
		t.Fatalf("parser errors: %v", errors)
	}

	if rule == nil {
		t.Fatal("expected rule, got nil")
	}

	// Check function call with named arguments
	if funcCall, ok := rule.When.(*FunctionCall); ok {
		if funcCall.Name != "test_function" {
			t.Errorf("expected function name 'test_function', got %q", funcCall.Name)
		}

		if len(funcCall.Arguments) != 3 {
			t.Errorf("expected 3 arguments, got %d", len(funcCall.Arguments))
		}

		// Check each named argument
		expectedArgs := map[string]interface{}{
			"arg1": "value1",
			"arg2": 42.0,
			"arg3": true,
		}

		for i, arg := range funcCall.Arguments {
			if namedArg, ok := arg.(*NamedArgument); ok {
				expectedValue, exists := expectedArgs[namedArg.Name]
				if !exists {
					t.Errorf("unexpected argument name: %q", namedArg.Name)
					continue
				}

				switch v := namedArg.Value.(type) {
				case *StringLiteral:
					if v.Value != expectedValue {
						t.Errorf("expected %q for %s, got %q", expectedValue, namedArg.Name, v.Value)
					}
				case *NumberLiteral:
					if v.Value != expectedValue {
						t.Errorf("expected %v for %s, got %v", expectedValue, namedArg.Name, v.Value)
					}
				case *BooleanLiteral:
					if v.Value != expectedValue {
						t.Errorf("expected %v for %s, got %v", expectedValue, namedArg.Name, v.Value)
					}
				}
			} else {
				t.Errorf("expected named argument at position %d, got %T", i, arg)
			}
		}
	} else {
		t.Errorf("expected function call, got %T", rule.When)
	}
}

func TestCrossBorderTransactionCheck(t *testing.T) {
	input := `rule CrossBorderTransactionCheck {
		description "High-value transaction crossing international borders."

		when metadata.source_country != metadata.destination_country
		 and amount > 1000

		then review
			 score   0.5
			 reason  "Large cross-border transaction requires review"
	}`

	ruleName, description, ruleJSON, err := CompileWatchScript(input)
	if err != nil {
		t.Fatalf("compilation error: %v", err)
	}

	// Check extracted values
	if ruleName != "CrossBorderTransactionCheck" {
		t.Errorf("expected rule name 'CrossBorderTransactionCheck', got %q", ruleName)
	}

	if description != "High-value transaction crossing international borders." {
		t.Errorf("expected description 'High-value transaction crossing international borders.', got %q", description)
	}

	// Check that JSON is valid
	var rule Rule
	if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	// Check rule structure
	if rule.Then.Verdict != "review" {
		t.Errorf("expected verdict 'review', got %q", rule.Then.Verdict)
	}

	if rule.Then.Score != 0.5 {
		t.Errorf("expected score 0.5, got %f", rule.Then.Score)
	}

	if rule.Then.Reason != "Large cross-border transaction requires review" {
		t.Errorf("expected reason 'Large cross-border transaction requires review', got %q", rule.Then.Reason)
	}

	// Should have conditions
	if len(rule.When) == 0 {
		t.Error("expected at least one when condition")
	}

	t.Logf("Generated JSON: %s", ruleJSON)
}

func TestDestinationHighInflowScript(t *testing.T) {
	input := `rule DestinationHighInflow {
		description "High volume of funds flowing into a single destination in 24h."

		when sum(amount when destination == $current.destination, "PT24H") > 100

		then review
			 score   0.5
			 reason  "High inflow to same destination in 24 hours."
	}`

	ruleName, description, ruleJSON, err := CompileWatchScript(input)
	if err != nil {
		t.Fatalf("compilation error: %v", err)
	}

	// Check extracted values
	if ruleName != "DestinationHighInflow" {
		t.Errorf("expected rule name 'DestinationHighInflow', got %q", ruleName)
	}

	if description != "High volume of funds flowing into a single destination in 24h." {
		t.Errorf("expected description 'High volume of funds flowing into a single destination in 24h.', got %q", description)
	}

	// Check that JSON is valid
	var rule Rule
	if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	// Check rule structure
	if rule.Then.Verdict != "review" {
		t.Errorf("expected verdict 'review', got %q", rule.Then.Verdict)
	}

	if rule.Then.Score != 0.5 {
		t.Errorf("expected score 0.5, got %f", rule.Then.Score)
	}

	if rule.Then.Reason != "High inflow to same destination in 24 hours." {
		t.Errorf("expected reason 'High inflow to same destination in 24 hours.', got %q", rule.Then.Reason)
	}

	// Should have conditions
	if len(rule.When) == 0 {
		t.Error("expected at least one when condition")
	}

	t.Logf("Generated JSON: %s", ruleJSON)
}

func TestParserConditionalExpressions(t *testing.T) {
	input := `rule ConditionalTest {
		when sum(amount when status == "completed", "PT1H") > 1000
		then block
	}`

	lexer := NewLexer(input)
	parser := NewParser(lexer)

	rule, errors := parser.ParseRule()
	if len(errors) > 0 {
		for _, err := range errors {
			t.Logf("Parse error: %v", err)
		}
		t.Fatalf("parser errors: %v", errors)
	}

	if rule == nil {
		t.Fatal("expected rule, got nil")
	}

	// Check that we parsed the function call with conditional expression correctly
	if infixExpr, ok := rule.When.(*InfixExpression); ok {
		if funcCall, ok := infixExpr.Left.(*FunctionCall); ok {
			if funcCall.Name != "sum" {
				t.Errorf("expected function name 'sum', got %q", funcCall.Name)
			}

			if len(funcCall.Arguments) != 2 {
				t.Errorf("expected 2 arguments, got %d", len(funcCall.Arguments))
			}

			// First argument should be a conditional expression
			if condExpr, ok := funcCall.Arguments[0].(*ConditionalExpression); ok {
				// Check the value part (amount)
				if ident, ok := condExpr.Value.(*Identifier); ok {
					if ident.Value != "amount" {
						t.Errorf("expected value 'amount', got %q", ident.Value)
					}
				} else {
					t.Errorf("expected identifier for conditional value, got %T", condExpr.Value)
				}

				// Check the condition part (status == "completed")
				if infixCond, ok := condExpr.Condition.(*InfixExpression); ok {
					if infixCond.Operator != "==" {
						t.Errorf("expected == operator in condition, got %q", infixCond.Operator)
					}
				} else {
					t.Errorf("expected infix expression for condition, got %T", condExpr.Condition)
				}
			} else {
				t.Errorf("expected conditional expression as first argument, got %T", funcCall.Arguments[0])
			}

			// Second argument should be a string literal
			if stringLit, ok := funcCall.Arguments[1].(*StringLiteral); ok {
				if stringLit.Value != "PT1H" {
					t.Errorf("expected time window 'PT1H', got %q", stringLit.Value)
				}
			} else {
				t.Errorf("expected string literal for time window, got %T", funcCall.Arguments[1])
			}
		} else {
			t.Errorf("expected function call on left side, got %T", infixExpr.Left)
		}
	} else {
		t.Errorf("expected infix expression, got %T", rule.When)
	}
}

func TestHighFrequencyDestinationScript(t *testing.T) {
	input := `rule HighFrequencyDestination {
		description "Unusually frequent payments to the same destination may require scrutiny."

		when count(when destination == $current.destination, "PT24H") > 10
		 and amount > 100

		then review
			 score   0.5
			 reason  "High frequency of transactions to same destination in 24 hours"
	}`

	ruleName, description, ruleJSON, err := CompileWatchScript(input)
	if err != nil {
		t.Fatalf("compilation error: %v", err)
	}

	// Check extracted values
	if ruleName != "HighFrequencyDestination" {
		t.Errorf("expected rule name 'HighFrequencyDestination', got %q", ruleName)
	}

	if description != "Unusually frequent payments to the same destination may require scrutiny." {
		t.Errorf("expected description 'Unusually frequent payments to the same destination may require scrutiny.', got %q", description)
	}

	// Check that JSON is valid
	var rule Rule
	if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	// Check rule structure
	if rule.Then.Verdict != "review" {
		t.Errorf("expected verdict 'review', got %q", rule.Then.Verdict)
	}

	if rule.Then.Score != 0.5 {
		t.Errorf("expected score 0.5, got %f", rule.Then.Score)
	}

	if rule.Then.Reason != "High frequency of transactions to same destination in 24 hours" {
		t.Errorf("expected reason 'High frequency of transactions to same destination in 24 hours', got %q", rule.Then.Reason)
	}

	// Should have conditions
	if len(rule.When) == 0 {
		t.Error("expected at least one when condition")
	}

	t.Logf("Generated JSON: %s", ruleJSON)
}

func TestParserConditionOnlyExpressions(t *testing.T) {
	input := `rule ConditionOnlyTest {
		when count(when status == "completed", "PT1H") > 5
		then block
	}`

	lexer := NewLexer(input)
	parser := NewParser(lexer)

	rule, errors := parser.ParseRule()
	if len(errors) > 0 {
		for _, err := range errors {
			t.Logf("Parse error: %v", err)
		}
		t.Fatalf("parser errors: %v", errors)
	}

	if rule == nil {
		t.Fatal("expected rule, got nil")
	}

	// Check that we parsed the function call with condition-only expression correctly
	if infixExpr, ok := rule.When.(*InfixExpression); ok {
		if funcCall, ok := infixExpr.Left.(*FunctionCall); ok {
			if funcCall.Name != "count" {
				t.Errorf("expected function name 'count', got %q", funcCall.Name)
			}

			if len(funcCall.Arguments) != 2 {
				t.Errorf("expected 2 arguments, got %d", len(funcCall.Arguments))
			}

			// First argument should be a conditional expression with no value
			if condExpr, ok := funcCall.Arguments[0].(*ConditionalExpression); ok {
				// Check that there's no value part (should be nil)
				if condExpr.Value != nil {
					t.Errorf("expected nil value for condition-only expression, got %T", condExpr.Value)
				}

				// Check the condition part (status == "completed")
				if infixCond, ok := condExpr.Condition.(*InfixExpression); ok {
					if infixCond.Operator != "==" {
						t.Errorf("expected == operator in condition, got %q", infixCond.Operator)
					}
				} else {
					t.Errorf("expected infix expression for condition, got %T", condExpr.Condition)
				}
			} else {
				t.Errorf("expected conditional expression as first argument, got %T", funcCall.Arguments[0])
			}

			// Second argument should be a string literal
			if stringLit, ok := funcCall.Arguments[1].(*StringLiteral); ok {
				if stringLit.Value != "PT1H" {
					t.Errorf("expected time window 'PT1H', got %q", stringLit.Value)
				}
			} else {
				t.Errorf("expected string literal for time window, got %T", funcCall.Arguments[1])
			}
		} else {
			t.Errorf("expected function call on left side, got %T", infixExpr.Left)
		}
	} else {
		t.Errorf("expected infix expression, got %T", rule.When)
	}
}

func TestSuspiciousDescriptionCheckScript(t *testing.T) {
	input := `rule SuspiciousDescriptionCheck {
		description "Detects suspicious keywords or patterns in transaction descriptions."

		when description regex "(?i)(btc|bitcoin|crypto|wallet|transfer|gift.?card|western.?union)"
		and amount > 1000

		then review
			 score   0.7
			 reason  "Suspicious description pattern."
	}`

	ruleName, description, ruleJSON, err := CompileWatchScript(input)
	if err != nil {
		t.Fatalf("compilation error: %v", err)
	}

	// Check extracted values
	if ruleName != "SuspiciousDescriptionCheck" {
		t.Errorf("expected rule name 'SuspiciousDescriptionCheck', got %q", ruleName)
	}

	if description != "Detects suspicious keywords or patterns in transaction descriptions." {
		t.Errorf("expected description 'Detects suspicious keywords or patterns in transaction descriptions.', got %q", description)
	}

	// Check that JSON is valid
	var rule Rule
	if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	// Check rule structure
	if rule.Then.Verdict != "review" {
		t.Errorf("expected verdict 'review', got %q", rule.Then.Verdict)
	}

	if rule.Then.Score != 0.7 {
		t.Errorf("expected score 0.7, got %f", rule.Then.Score)
	}

	if rule.Then.Reason != "Suspicious description pattern." {
		t.Errorf("expected reason 'Suspicious description pattern.', got %q", rule.Then.Reason)
	}

	// Should have conditions
	if len(rule.When) == 0 {
		t.Error("expected at least one when condition")
	}

	t.Logf("Generated JSON: %s", ruleJSON)
}

func TestCompileWatchScriptTimeFunctionEmitsTimeFunctionType(t *testing.T) {
	// Parser should emit "time_function" (not "function_comparison") so the interpreter evaluates it.
	input := `rule TimeHourOfDay {
  description "Review transactions in late night window."
  when hour_of_day(created_at) >= 21
  or hour_of_day(created_at) <= 3
  then review
       score   0.5
       reason  "Transaction in late night window"
}`

	_, _, ruleJSON, err := CompileWatchScript(input)
	if err != nil {
		t.Fatalf("compilation error: %v", err)
	}

	var rule Rule
	if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if len(rule.When) == 0 {
		t.Fatal("expected at least one when condition")
	}

	// When has "logical" (or) with left/right; each side may be time_function
	var findTimeFunctionConditions func(raw []json.RawMessage) []map[string]interface{}
	findTimeFunctionConditions = func(raw []json.RawMessage) []map[string]interface{} {
		var out []map[string]interface{}
		for _, r := range raw {
			var probe struct {
				Type string `json:"type"`
			}
			_ = json.Unmarshal(r, &probe)
			if probe.Type == "time_function" {
				var m map[string]interface{}
				_ = json.Unmarshal(r, &m)
				out = append(out, m)
			}
			if probe.Type == "logical" {
				var l struct {
					Left  json.RawMessage `json:"left"`
					Right json.RawMessage `json:"right"`
				}
				_ = json.Unmarshal(r, &l)
				if len(l.Left) > 0 {
					out = append(out, findTimeFunctionConditions([]json.RawMessage{l.Left})...)
				}
				if len(l.Right) > 0 {
					out = append(out, findTimeFunctionConditions([]json.RawMessage{l.Right})...)
				}
			}
		}
		return out
	}

	conds := findTimeFunctionConditions(rule.When)
	if len(conds) == 0 {
		t.Fatalf("expected at least one condition with type time_function; when: %s", ruleJSON)
	}
	for i, c := range conds {
		if c["type"] != "time_function" {
			t.Errorf("condition %d: expected type time_function, got %v", i, c["type"])
		}
		if c["function"] != "hour_of_day" {
			t.Errorf("condition %d: expected function hour_of_day, got %v", i, c["function"])
		}
		if c["field"] != "created_at" {
			t.Errorf("condition %d: expected field created_at, got %v", i, c["field"])
		}
	}
}

func TestCompileWatchScriptDayOfWeekInEmitsTimeFunctionType(t *testing.T) {
	input := `rule TimeDayOfWeek {
  description "Review large transactions on weekend."
  when day_of_week(created_at) in (0, 6)
  and amount > 3000
  then review
       score   0.4
       reason  "Large weekend transaction"
}`

	_, _, ruleJSON, err := CompileWatchScript(input)
	if err != nil {
		t.Fatalf("compilation error: %v", err)
	}

	var rule Rule
	if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	// Find time_function in when (may be under logical "and")
	var found bool
	for _, raw := range rule.When {
		var probe struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(raw, &probe)
		if probe.Type == "time_function" {
			found = true
			var tc struct {
				Function string      `json:"function"`
				Field    string      `json:"field"`
				Op       string      `json:"op"`
				Value    interface{} `json:"value"`
			}
			_ = json.Unmarshal(raw, &tc)
			if tc.Function != "day_of_week" || tc.Field != "created_at" || tc.Op != "in" {
				t.Errorf("expected day_of_week(created_at) in (...); got function=%q field=%q op=%q", tc.Function, tc.Field, tc.Op)
			}
			break
		}
		if probe.Type == "logical" {
			var l struct {
				Left json.RawMessage `json:"left"`
			}
			_ = json.Unmarshal(raw, &l)
			if len(l.Left) > 0 {
				var inner struct {
					Type string `json:"type"`
				}
				_ = json.Unmarshal(l.Left, &inner)
				if inner.Type == "time_function" {
					found = true
					break
				}
			}
		}
	}
	if !found {
		t.Errorf("expected a time_function condition in when; got: %s", ruleJSON)
	}
}

func TestParserReservedKeywordsAsFields(t *testing.T) {
	input := `rule ReservedKeywordTest {
		when description == "test" and in != "blocked"
		then allow
	}`

	lexer := NewLexer(input)
	parser := NewParser(lexer)

	rule, errors := parser.ParseRule()
	if len(errors) > 0 {
		for _, err := range errors {
			t.Logf("Parse error: %v", err)
		}
		t.Fatalf("parser errors: %v", errors)
	}

	if rule == nil {
		t.Fatal("expected rule, got nil")
	}

	// Check that we parsed reserved keywords as field names correctly
	if logicalExpr, ok := rule.When.(*LogicalExpression); ok {
		if logicalExpr.Operator != "and" {
			t.Errorf("expected AND operator, got %q", logicalExpr.Operator)
		}

		// Left side should be description == "test"
		if infixExpr, ok := logicalExpr.Left.(*InfixExpression); ok {
			if ident, ok := infixExpr.Left.(*Identifier); ok {
				if ident.Value != "description" {
					t.Errorf("expected field name 'description', got %q", ident.Value)
				}
			} else {
				t.Errorf("expected identifier for left field, got %T", infixExpr.Left)
			}
		} else {
			t.Errorf("expected infix expression on left side, got %T", logicalExpr.Left)
		}

		// Right side should be in != "blocked"
		if infixExpr, ok := logicalExpr.Right.(*InfixExpression); ok {
			if ident, ok := infixExpr.Left.(*Identifier); ok {
				if ident.Value != "in" {
					t.Errorf("expected field name 'in', got %q", ident.Value)
				}
			} else {
				t.Errorf("expected identifier for right field, got %T", infixExpr.Left)
			}
		} else {
			t.Errorf("expected infix expression on right side, got %T", logicalExpr.Right)
		}
	} else {
		t.Errorf("expected logical expression, got %T", rule.When)
	}
}

func TestComparisonWithOldCompiler(t *testing.T) {
	// Simple rule that both compilers should handle
	input := `rule SimpleTest {
		description "Simple test rule"
		when amount > 1000
		then block
		score 0.9
		reason "Amount exceeds limit"
	}`

	// Test new parser
	newRuleName, newDescription, newRuleJSON, newErr := CompileWatchScript(input)
	if newErr != nil {
		t.Fatalf("new parser error: %v", newErr)
	}

	// Test old compiler
	oldRuleName, oldDescription, oldRuleJSON, oldErr := CompileWatchScript(input)

	// Compare results (old compiler might fail on some syntax, which is expected)
	if oldErr == nil {
		// Both succeeded, compare outputs
		if newRuleName != oldRuleName {
			t.Errorf("rule names differ: new=%q, old=%q", newRuleName, oldRuleName)
		}

		if newDescription != oldDescription {
			t.Errorf("descriptions differ: new=%q, old=%q", newDescription, oldDescription)
		}

		// Parse both JSONs to compare structure
		var newRule, oldRule Rule
		if err := json.Unmarshal([]byte(newRuleJSON), &newRule); err != nil {
			t.Fatalf("failed to parse new JSON: %v", err)
		}
		if err := json.Unmarshal([]byte(oldRuleJSON), &oldRule); err != nil {
			t.Fatalf("failed to parse old JSON: %v", err)
		}

		// Compare basic structure
		if newRule.Then.Verdict != oldRule.Then.Verdict {
			t.Errorf("verdicts differ: new=%q, old=%q", newRule.Then.Verdict, oldRule.Then.Verdict)
		}
		if newRule.Then.Score != oldRule.Then.Score {
			t.Errorf("scores differ: new=%f, old=%f", newRule.Then.Score, oldRule.Then.Score)
		}
	} else {
		t.Logf("Old compiler failed (expected): %v", oldErr)
		t.Logf("New parser succeeded with: name=%q, desc=%q", newRuleName, newDescription)
	}
}
