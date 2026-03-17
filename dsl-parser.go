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
	"strconv"
	"strings"
)

type TokenType int

const (
	// Literals
	IDENTIFIER TokenType = iota
	STRING
	NUMBER
	BOOLEAN

	// Keywords
	RULE
	WHEN
	THEN
	AND
	OR
	DESCRIPTION
	IN
	REGEX
	NOT_REGEX

	// Operators
	EQ   // ==
	NE   // !=
	GT   // >
	GTE  // >=
	LT   // <
	LTE  // <=
	PLUS // +

	// Delimiters
	LPAREN // (
	RPAREN // )
	LBRACE // {
	RBRACE // }
	COMMA  // ,
	COLON  // :
	DOT    // .
	DOLLAR // $

	// Special
	NEWLINE
	EOF
	ILLEGAL
)

var tokenNames = map[TokenType]string{
	IDENTIFIER:  "IDENTIFIER",
	STRING:      "STRING",
	NUMBER:      "NUMBER",
	BOOLEAN:     "BOOLEAN",
	RULE:        "RULE",
	WHEN:        "WHEN",
	THEN:        "THEN",
	AND:         "AND",
	OR:          "OR",
	DESCRIPTION: "DESCRIPTION",
	IN:          "IN",
	REGEX:       "REGEX",
	NOT_REGEX:   "NOT_REGEX",
	EQ:          "==",
	NE:          "!=",
	GT:          ">",
	GTE:         ">=",
	LT:          "<",
	LTE:         "<=",
	PLUS:        "+",
	LPAREN:      "(",
	RPAREN:      ")",
	LBRACE:      "{",
	RBRACE:      "}",
	COMMA:       ",",
	COLON:       ":",
	DOT:         ".",
	DOLLAR:      "$",
	NEWLINE:     "NEWLINE",
	EOF:         "EOF",
	ILLEGAL:     "ILLEGAL",
}

func (t TokenType) String() string {
	if name, ok := tokenNames[t]; ok {
		return name
	}
	return fmt.Sprintf("TokenType(%d)", int(t))
}

type Token struct {
	Type     TokenType
	Literal  string
	Line     int
	Column   int
	Position int
}

func (t Token) String() string {
	return fmt.Sprintf("{%s: %q at %d:%d}", t.Type, t.Literal, t.Line, t.Column)
}

// Lexer tokenizes the input DSL script
type Lexer struct {
	input        string
	position     int  // current position in input (points to current char)
	readPosition int  // current reading position in input (after current char)
	ch           byte // current char under examination
	line         int  // current line number
	column       int  // current column number
}

// NewLexer creates a new lexer instance
func NewLexer(input string) *Lexer {
	l := &Lexer{
		input:  input,
		line:   1,
		column: 0,
	}
	l.readChar()
	return l
}

func (l *Lexer) readChar() {
	if l.readPosition >= len(l.input) {
		l.ch = 0
	} else {
		l.ch = l.input[l.readPosition]
	}
	l.position = l.readPosition
	l.readPosition++

	if l.ch == '\n' {
		l.line++
		l.column = 0
	} else {
		l.column++
	}
}

// peekChar returns the next character without advancing position
func (l *Lexer) peekChar() byte {
	if l.readPosition >= len(l.input) {
		return 0
	}
	return l.input[l.readPosition]
}

// skipWhitespace skips whitespace characters except newlines
func (l *Lexer) skipWhitespace() {
	for l.ch == ' ' || l.ch == '\t' || l.ch == '\r' {
		l.readChar()
	}
}

func (l *Lexer) readIdentifier() string {
	position := l.position
	for isLetter(l.ch) || isDigit(l.ch) || l.ch == '_' {
		l.readChar()
	}
	return l.input[position:l.position]
}

func (l *Lexer) readNumber() string {
	position := l.position
	for isDigit(l.ch) {
		l.readChar()
	}

	if l.ch == '.' && isDigit(l.peekChar()) {
		l.readChar()
		for isDigit(l.ch) {
			l.readChar()
		}
	}

	return l.input[position:l.position]
}

func (l *Lexer) readString() (string, error) {
	position := l.position + 1
	for {
		l.readChar()
		if l.ch == '"' || l.ch == 0 {
			break
		}
		if l.ch == '\\' {
			l.readChar()
		}
	}

	if l.ch != '"' {
		return "", fmt.Errorf("unterminated string at line %d, column %d", l.line, l.column)
	}

	str := l.input[position:l.position]
	return str, nil
}

func (l *Lexer) NextToken() (Token, error) {
	var tok Token

	l.skipWhitespace()

	tok.Line = l.line
	tok.Column = l.column
	tok.Position = l.position

	switch l.ch {
	case '=':
		if l.peekChar() == '=' {
			l.readChar()
			tok.Type = EQ
			tok.Literal = "=="
		} else {
			tok.Type = ILLEGAL
			tok.Literal = string(l.ch)
		}
	case '!':
		if l.peekChar() == '=' {
			l.readChar()
			tok.Type = NE
			tok.Literal = "!="
		} else {
			tok.Type = ILLEGAL
			tok.Literal = string(l.ch)
		}
	case '>':
		if l.peekChar() == '=' {
			l.readChar()
			tok.Type = GTE
			tok.Literal = ">="
		} else {
			tok.Type = GT
			tok.Literal = ">"
		}
	case '<':
		if l.peekChar() == '=' {
			l.readChar()
			tok.Type = LTE
			tok.Literal = "<="
		} else {
			tok.Type = LT
			tok.Literal = "<"
		}
	case '+':
		tok.Type = PLUS
		tok.Literal = "+"
	case '(':
		tok.Type = LPAREN
		tok.Literal = "("
	case ')':
		tok.Type = RPAREN
		tok.Literal = ")"
	case '{':
		tok.Type = LBRACE
		tok.Literal = "{"
	case '}':
		tok.Type = RBRACE
		tok.Literal = "}"
	case ',':
		tok.Type = COMMA
		tok.Literal = ","
	case ':':
		tok.Type = COLON
		tok.Literal = ":"
	case '.':
		tok.Type = DOT
		tok.Literal = "."
	case '$':
		tok.Type = DOLLAR
		tok.Literal = "$"
	case '\n':
		tok.Type = NEWLINE
		tok.Literal = "\\n"
	case '"':
		str, err := l.readString()
		if err != nil {
			return tok, err
		}
		tok.Type = STRING
		tok.Literal = str
	case 0:
		tok.Type = EOF
		tok.Literal = ""
	default:
		if isLetter(l.ch) {
			tok.Literal = l.readIdentifier()
			tok.Type = lookupIdent(tok.Literal)
			return tok, nil
		} else if isDigit(l.ch) {
			tok.Literal = l.readNumber()
			tok.Type = NUMBER
			return tok, nil
		} else {
			tok.Type = ILLEGAL
			tok.Literal = string(l.ch)
		}
	}

	l.readChar()
	return tok, nil
}

func lookupIdent(ident string) TokenType {
	keywords := map[string]TokenType{
		"rule":        RULE,
		"when":        WHEN,
		"then":        THEN,
		"and":         AND,
		"or":          OR,
		"description": DESCRIPTION,
		"in":          IN,
		"regex":       REGEX,
		"not_regex":   NOT_REGEX,
		"true":        BOOLEAN,
		"false":       BOOLEAN,
	}

	if tok, ok := keywords[strings.ToLower(ident)]; ok {
		return tok
	}
	return IDENTIFIER
}

func isLetter(ch byte) bool {
	return 'a' <= ch && ch <= 'z' || 'A' <= ch && ch <= 'Z' || ch == '_'
}

func isDigit(ch byte) bool {
	return '0' <= ch && ch <= '9'
}

type Node interface {
	String() string
}

type Statement interface {
	Node
	statementNode()
}

type Expression interface {
	Node
	expressionNode()
}

type RuleStatement struct {
	Name        *Identifier
	Description *StringLiteral
	When        Expression
	Then        *ActionExpression
}

func (rs *RuleStatement) statementNode() {}
func (rs *RuleStatement) String() string {
	return fmt.Sprintf("Rule(%s)", rs.Name.Value)
}

type Identifier struct {
	Token Token
	Value string
}

func (i *Identifier) expressionNode() {}
func (i *Identifier) String() string  { return i.Value }

type StringLiteral struct {
	Token Token
	Value string
}

func (sl *StringLiteral) expressionNode() {}
func (sl *StringLiteral) String() string  { return fmt.Sprintf("\"%s\"", sl.Value) }

type NumberLiteral struct {
	Token Token
	Value float64
}

func (nl *NumberLiteral) expressionNode() {}
func (nl *NumberLiteral) String() string  { return fmt.Sprintf("%g", nl.Value) }

type BooleanLiteral struct {
	Token Token
	Value bool
}

func (bl *BooleanLiteral) expressionNode() {}
func (bl *BooleanLiteral) String() string  { return fmt.Sprintf("%t", bl.Value) }

type FieldPath struct {
	Token Token
	Parts []string
}

func (fp *FieldPath) expressionNode() {}
func (fp *FieldPath) String() string  { return strings.Join(fp.Parts, ".") }

type Variable struct {
	Token Token
	Name  string
}

func (v *Variable) expressionNode() {}
func (v *Variable) String() string  { return "$" + v.Name }

type InfixExpression struct {
	Token    Token
	Left     Expression
	Operator string
	Right    Expression
}

func (ie *InfixExpression) expressionNode() {}
func (ie *InfixExpression) String() string {
	return fmt.Sprintf("(%s %s %s)", ie.Left.String(), ie.Operator, ie.Right.String())
}

type LogicalExpression struct {
	Token    Token
	Left     Expression
	Operator string
	Right    Expression
}

func (le *LogicalExpression) expressionNode() {}
func (le *LogicalExpression) String() string {
	return fmt.Sprintf("(%s %s %s)", le.Left.String(), le.Operator, le.Right.String())
}

type FunctionCall struct {
	Token     Token
	Name      string
	Arguments []Expression
}

func (fc *FunctionCall) expressionNode() {}
func (fc *FunctionCall) String() string {
	args := make([]string, len(fc.Arguments))
	for i, arg := range fc.Arguments {
		args[i] = arg.String()
	}
	return fmt.Sprintf("%s(%s)", fc.Name, strings.Join(args, ", "))
}

type ActionExpression struct {
	Token   Token
	Verdict string
	Score   *NumberLiteral
	Reason  *StringLiteral
}

func (ae *ActionExpression) expressionNode() {}
func (ae *ActionExpression) String() string {
	return fmt.Sprintf("Action(%s, %s, %s)", ae.Verdict, ae.Score.String(), ae.Reason.String())
}

type ArrayLiteral struct {
	Token    Token
	Elements []Expression
}

func (al *ArrayLiteral) expressionNode() {}
func (al *ArrayLiteral) String() string {
	elements := make([]string, len(al.Elements))
	for i, elem := range al.Elements {
		elements[i] = elem.String()
	}
	return fmt.Sprintf("(%s)", strings.Join(elements, ", "))
}

type ObjectLiteral struct {
	Token Token
	Pairs map[string]Expression
}

func (ol *ObjectLiteral) expressionNode() {}
func (ol *ObjectLiteral) String() string {
	var pairs []string
	for key, value := range ol.Pairs {
		pairs = append(pairs, fmt.Sprintf("%s: %s", key, value.String()))
	}
	return fmt.Sprintf("{%s}", strings.Join(pairs, ", "))
}

type NamedArgument struct {
	Token Token
	Name  string
	Value Expression
}

func (na *NamedArgument) expressionNode() {}
func (na *NamedArgument) String() string {
	return fmt.Sprintf("%s: %s", na.Name, na.Value.String())
}

type ConditionalExpression struct {
	Token     Token
	Value     Expression // The value expression (e.g., "amount")
	Condition Expression // The condition expression (e.g., "destination == $current.destination")
}

func (ce *ConditionalExpression) expressionNode() {}
func (ce *ConditionalExpression) String() string {
	return fmt.Sprintf("%s when %s", ce.Value.String(), ce.Condition.String())
}

type ParseError struct {
	Message string
	Line    int
	Column  int
	Token   Token
}

func (pe *ParseError) Error() string {
	return fmt.Sprintf("parse error at line %d, column %d: %s (got %s)",
		pe.Line, pe.Column, pe.Message, pe.Token.Type)
}

type Parser struct {
	lexer *Lexer

	curToken  Token
	peekToken Token

	errors []ParseError
}

func NewParser(lexer *Lexer) *Parser {
	p := &Parser{
		lexer:  lexer,
		errors: []ParseError{},
	}

	// Read two tokens, so curToken and peekToken are both set
	p.nextToken()
	p.nextToken()

	return p
}

func (p *Parser) nextToken() {
	p.curToken = p.peekToken
	var err error
	p.peekToken, err = p.lexer.NextToken()
	if err != nil {
		p.addError(fmt.Sprintf("lexer error: %s", err.Error()))
	}
}

// addError adds a parse error
func (p *Parser) addError(msg string) {
	p.errors = append(p.errors, ParseError{
		Message: msg,
		Line:    p.curToken.Line,
		Column:  p.curToken.Column,
		Token:   p.curToken,
	})
}

func (p *Parser) expectToken(t TokenType) bool {
	if p.curToken.Type == t {
		p.nextToken()
		return true
	}
	p.addError(fmt.Sprintf("expected %s, got %s", t, p.curToken.Type))
	return false
}

func (p *Parser) skipNewlines() {
	for p.curToken.Type == NEWLINE {
		p.nextToken()
	}
}

// ParseRule parses a complete rule statement
func (p *Parser) ParseRule() (*RuleStatement, []ParseError) {
	rule := &RuleStatement{}

	p.skipNewlines()

	if p.curToken.Type == RULE {
		p.nextToken()
	}

	if p.curToken.Type != IDENTIFIER {
		p.addError("expected rule name")
		return nil, p.errors
	}

	rule.Name = &Identifier{
		Token: p.curToken,
		Value: p.curToken.Literal,
	}
	p.nextToken()

	if !p.expectToken(LBRACE) {
		return nil, p.errors
	}

	p.skipNewlines()

	for p.curToken.Type != RBRACE && p.curToken.Type != EOF {
		switch p.curToken.Type {
		case DESCRIPTION:
			p.nextToken()
			if p.curToken.Type != STRING {
				p.addError("expected string after description")
				return nil, p.errors
			}
			rule.Description = &StringLiteral{
				Token: p.curToken,
				Value: p.curToken.Literal,
			}
			p.nextToken()

		case WHEN:
			p.nextToken()
			condition, err := p.parseWhenClause()
			if err != nil {
				return nil, p.errors
			}
			rule.When = condition

		case THEN:
			p.nextToken()
			action, err := p.parseThenClause()
			if err != nil {
				return nil, p.errors
			}
			rule.Then = action

		default:
			p.addError(fmt.Sprintf("unexpected token in rule body: %s", p.curToken.Type))
			p.nextToken()
		}

		p.skipNewlines()
	}

	if !p.expectToken(RBRACE) {
		return nil, p.errors
	}

	if rule.When == nil {
		p.addError("rule missing 'when' clause")
	}
	if rule.Then == nil {
		p.addError("rule missing 'then' clause")
	}

	if len(p.errors) > 0 {
		return nil, p.errors
	}

	return rule, nil
}

func (p *Parser) parseWhenClause() (Expression, error) {
	expr := p.parseLogicalExpression()

	p.skipNewlines()
	for p.curToken.Type == AND || p.curToken.Type == OR {
		operator := strings.ToLower(p.curToken.Literal)
		operatorToken := p.curToken
		p.nextToken()
		p.skipNewlines()

		right := p.parseInfixExpression()
		if right == nil {
			p.addError("expected expression after logical operator")
			return nil, fmt.Errorf("parse error")
		}

		expr = &LogicalExpression{
			Token:    operatorToken,
			Left:     expr,
			Operator: operator,
			Right:    right,
		}

		p.skipNewlines()
	}

	return expr, nil
}

func (p *Parser) parseThenClause() (*ActionExpression, error) {
	action := &ActionExpression{Token: p.curToken}

	if p.curToken.Type != IDENTIFIER {
		p.addError("expected verdict (allow, block, review)")
		return nil, fmt.Errorf("parse error")
	}

	verdict := strings.ToLower(p.curToken.Literal)
	if verdict != "allow" && verdict != "block" && verdict != "review" &&
		verdict != "approve" && verdict != "deny" && verdict != "alert" {
		p.addError(fmt.Sprintf("invalid verdict: %s", verdict))
		return nil, fmt.Errorf("parse error")
	}

	action.Verdict = verdict
	p.nextToken()
	p.skipNewlines()

	for p.curToken.Type != RBRACE && p.curToken.Type != EOF {
		switch strings.ToLower(p.curToken.Literal) {
		case "score":
			p.nextToken()
			if p.curToken.Type != NUMBER {
				p.addError("expected number after 'score'")
				return nil, fmt.Errorf("parse error")
			}
			score, err := strconv.ParseFloat(p.curToken.Literal, 64)
			if err != nil {
				p.addError(fmt.Sprintf("invalid score value: %s", p.curToken.Literal))
				return nil, fmt.Errorf("parse error")
			}
			action.Score = &NumberLiteral{
				Token: p.curToken,
				Value: score,
			}
			p.nextToken()

		case "reason":
			p.nextToken()
			if p.curToken.Type != STRING {
				p.addError("expected string after 'reason'")
				return nil, fmt.Errorf("parse error")
			}
			action.Reason = &StringLiteral{
				Token: p.curToken,
				Value: p.curToken.Literal,
			}
			p.nextToken()

		default:
			p.addError(fmt.Sprintf("unexpected token in then clause: %s", p.curToken.Literal))
			p.nextToken()
		}

		p.skipNewlines()
	}

	if action.Score == nil {
		action.Score = &NumberLiteral{Value: 0.0}
	}
	if action.Reason == nil {
		action.Reason = &StringLiteral{Value: "No reason provided"}
	}

	return action, nil
}

func (p *Parser) parseExpression() Expression {
	return p.parseLogicalExpression()
}

func (p *Parser) parseLogicalExpression() Expression {
	left := p.parseInfixExpression()
	if left == nil {
		return nil
	}

	for p.curToken.Type == AND || p.curToken.Type == OR {
		operator := strings.ToLower(p.curToken.Literal)
		operatorToken := p.curToken
		p.nextToken()
		p.skipNewlines()

		right := p.parseInfixExpression()
		if right == nil {
			p.addError("expected expression after logical operator")
			return nil
		}

		left = &LogicalExpression{
			Token:    operatorToken,
			Left:     left,
			Operator: operator,
			Right:    right,
		}

		p.skipNewlines()
	}

	return left
}

func (p *Parser) parseInfixExpression() Expression {
	left := p.parsePrimaryExpression()
	if left == nil {
		return nil
	}

	if p.isInfixOperator(p.curToken.Type) {
		operator := p.curToken.Literal
		operatorToken := p.curToken
		p.nextToken()

		right := p.parsePrimaryExpression()
		if right == nil {
			p.addError("expected expression after operator")
			return nil
		}

		return &InfixExpression{
			Token:    operatorToken,
			Left:     left,
			Operator: operator,
			Right:    right,
		}
	}

	return left
}

func (p *Parser) parsePrimaryExpression() Expression {
	switch p.curToken.Type {
	case IDENTIFIER:
		return p.parseIdentifierOrFieldPath()
	case STRING:
		return p.parseStringLiteral()
	case NUMBER:
		return p.parseNumberLiteral()
	case BOOLEAN:
		return p.parseBooleanLiteral()
	case DOLLAR:
		return p.parseVariable()
	case LPAREN:
		return p.parseArrayLiteral()
	case LBRACE:
		return p.parseObjectLiteral()
	case DESCRIPTION, IN, REGEX, NOT_REGEX:
		return p.parseReservedKeywordAsIdentifier()
	default:
		p.addError(fmt.Sprintf("unexpected token: %s", p.curToken.Type))
		return nil
	}
}

func (p *Parser) parseReservedKeywordAsIdentifier() Expression {
	token := p.curToken
	literal := p.curToken.Literal
	p.nextToken()

	if p.curToken.Type == LPAREN {
		p.curToken = token
		return p.parseFunctionCall()
	}

	parts := []string{literal}

	for p.curToken.Type == DOT {
		p.nextToken()
		if p.curToken.Type != IDENTIFIER && !p.isReservedKeywordUsedAsIdentifier() {
			p.addError("expected identifier after '.'")
			return nil
		}
		parts = append(parts, p.curToken.Literal)
		p.nextToken()
	}

	if len(parts) == 1 {
		return &Identifier{Token: token, Value: parts[0]}
	}

	return &FieldPath{Token: token, Parts: parts}
}

func (p *Parser) isReservedKeywordUsedAsIdentifier() bool {
	switch p.curToken.Type {
	case DESCRIPTION, WHEN, THEN, AND, OR, IN, REGEX, NOT_REGEX:
		return true
	default:
		return false
	}
}

func (p *Parser) parseIdentifierOrFieldPath() Expression {
	if p.peekToken.Type == LPAREN {
		return p.parseFunctionCall()
	}

	// Build field path
	parts := []string{p.curToken.Literal}
	token := p.curToken
	p.nextToken()

	// Handle dot notation
	for p.curToken.Type == DOT {
		p.nextToken()
		if p.curToken.Type != IDENTIFIER {
			p.addError("expected identifier after '.'")
			return nil
		}
		parts = append(parts, p.curToken.Literal)
		p.nextToken()
	}

	if len(parts) == 1 {
		return &Identifier{Token: token, Value: parts[0]}
	}

	return &FieldPath{Token: token, Parts: parts}
}

func (p *Parser) parseFunctionCall() Expression {
	name := p.curToken.Literal
	token := p.curToken
	p.nextToken()
	p.nextToken()

	var args []Expression

	p.skipNewlines()

	if p.curToken.Type != RPAREN {
		args = append(args, p.parseFunctionArgument())

		for p.curToken.Type == COMMA {
			p.nextToken()
			p.skipNewlines()
			if p.curToken.Type == RBRACE || p.curToken.Type == RPAREN {
				break
			}
			args = append(args, p.parseFunctionArgument())
		}
	}

	p.skipNewlines() // Allow newlines before closing paren

	if !p.expectToken(RPAREN) {
		return nil
	}

	return &FunctionCall{
		Token:     token,
		Name:      name,
		Arguments: args,
	}
}

func (p *Parser) parseFunctionArgument() Expression {
	if p.curToken.Type == IDENTIFIER && p.peekToken.Type == COLON {
		key := p.curToken.Literal
		keyToken := p.curToken
		p.nextToken()
		p.nextToken()

		p.skipNewlines()

		value := p.parseExpression()
		if value == nil {
			return nil
		}

		return &NamedArgument{
			Token: keyToken,
			Name:  key,
			Value: value,
		}
	}

	if p.curToken.Type == WHEN {
		whenToken := p.curToken
		p.nextToken()

		condition := p.parseLogicalExpression()
		if condition == nil {
			p.addError("expected condition after 'when'")
			return nil
		}

		return &ConditionalExpression{
			Token:     whenToken,
			Value:     nil,
			Condition: condition,
		}
	}

	expr := p.parseInfixExpression()
	if expr == nil {
		return nil
	}

	if p.curToken.Type == WHEN {
		whenToken := p.curToken
		p.nextToken()

		condition := p.parseLogicalExpression()
		if condition == nil {
			p.addError("expected condition after 'when'")
			return nil
		}

		return &ConditionalExpression{
			Token:     whenToken,
			Value:     expr,
			Condition: condition,
		}
	}

	for p.curToken.Type == AND || p.curToken.Type == OR {
		operator := strings.ToLower(p.curToken.Literal)
		operatorToken := p.curToken
		p.nextToken()
		p.skipNewlines()

		right := p.parseInfixExpression()
		if right == nil {
			p.addError("expected expression after logical operator")
			return nil
		}

		expr = &LogicalExpression{
			Token:    operatorToken,
			Left:     expr,
			Operator: operator,
			Right:    right,
		}

		p.skipNewlines()
	}

	return expr
}

func (p *Parser) parseStringLiteral() Expression {
	literal := &StringLiteral{
		Token: p.curToken,
		Value: p.curToken.Literal,
	}
	p.nextToken()
	return literal
}

func (p *Parser) parseNumberLiteral() Expression {
	value, err := strconv.ParseFloat(p.curToken.Literal, 64)
	if err != nil {
		p.addError(fmt.Sprintf("invalid number: %s", p.curToken.Literal))
		return nil
	}

	literal := &NumberLiteral{
		Token: p.curToken,
		Value: value,
	}
	p.nextToken()
	return literal
}

func (p *Parser) parseBooleanLiteral() Expression {
	value := strings.ToLower(p.curToken.Literal) == "true"

	literal := &BooleanLiteral{
		Token: p.curToken,
		Value: value,
	}
	p.nextToken()
	return literal
}

func (p *Parser) parseVariable() Expression {
	p.nextToken()

	if p.curToken.Type != IDENTIFIER {
		p.addError("expected identifier after '$'")
		return nil
	}

	parts := []string{p.curToken.Literal}
	token := p.curToken
	p.nextToken()

	for p.curToken.Type == DOT {
		p.nextToken()
		if p.curToken.Type != IDENTIFIER {
			p.addError("expected identifier after '.'")
			return nil
		}
		parts = append(parts, p.curToken.Literal)
		p.nextToken()
	}

	return &Variable{
		Token: token,
		Name:  strings.Join(parts, "."),
	}
}

func (p *Parser) parseArrayLiteral() Expression {
	token := p.curToken
	p.nextToken()

	var elements []Expression

	p.skipNewlines()

	if p.curToken.Type != RPAREN {
		elements = append(elements, p.parseExpression())

		for p.curToken.Type == COMMA {
			p.nextToken()
			p.skipNewlines()
			if p.curToken.Type == RPAREN {
				break
			}
			elements = append(elements, p.parseExpression())
		}
	}

	p.skipNewlines() // Allow newlines before closing paren

	if !p.expectToken(RPAREN) {
		return nil
	}

	return &ArrayLiteral{
		Token:    token,
		Elements: elements,
	}
}

func (p *Parser) parseObjectLiteral() Expression {
	token := p.curToken
	p.nextToken()

	pairs := make(map[string]Expression)

	p.skipNewlines()

	if p.curToken.Type != RBRACE {
		if p.curToken.Type != IDENTIFIER {
			p.addError("expected identifier for object key")
			return nil
		}

		key := p.curToken.Literal
		p.nextToken()

		if !p.expectToken(COLON) {
			return nil
		}

		p.skipNewlines()

		value := p.parseExpression()
		if value == nil {
			return nil
		}

		pairs[key] = value

		for p.curToken.Type == COMMA {
			p.nextToken()
			p.skipNewlines()

			if p.curToken.Type == RBRACE {
				break
			}

			if p.curToken.Type != IDENTIFIER {
				p.addError("expected identifier for object key")
				return nil
			}

			key = p.curToken.Literal
			p.nextToken()

			if !p.expectToken(COLON) {
				return nil
			}

			p.skipNewlines()

			value = p.parseExpression()
			if value == nil {
				return nil
			}

			pairs[key] = value
		}
	}

	p.skipNewlines()

	if !p.expectToken(RBRACE) {
		return nil
	}

	return &ObjectLiteral{
		Token: token,
		Pairs: pairs,
	}
}

// isInfixOperator checks if a token is an infix operator
func (p *Parser) isInfixOperator(tokenType TokenType) bool {
	switch tokenType {
	case EQ, NE, GT, GTE, LT, LTE, IN, REGEX, NOT_REGEX, PLUS:
		return true
	default:
		return false
	}
}

func CompileWatchScript(scriptContent string) (ruleName, description, ruleJSON string, err error) {
	lexer := NewLexer(scriptContent)
	parser := NewParser(lexer)

	rule, parseErrors := parser.ParseRule()
	if len(parseErrors) > 0 {
		var errorMsgs []string
		for _, pe := range parseErrors {
			errorMsgs = append(errorMsgs, pe.Error())
		}
		return "", "", "", fmt.Errorf("parse errors:\n%s", strings.Join(errorMsgs, "\n"))
	}

	if rule == nil {
		return "", "", "", fmt.Errorf("failed to parse rule")
	}

	ruleName = rule.Name.Value
	if rule.Description != nil {
		description = rule.Description.Value
	}

	dslRule, err := astToRule(rule)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to convert AST to rule: %w", err)
	}

	jsonBytes, err := json.Marshal(dslRule)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to marshal rule to JSON: %w", err)
	}

	ruleJSON = string(jsonBytes)
	return ruleName, description, ruleJSON, nil
}

func astToRule(ruleAST *RuleStatement) (*Rule, error) {
	rule := &Rule{
		When: make([]json.RawMessage, 0),
		Then: Action{
			Verdict: ruleAST.Then.Verdict,
			Score:   ruleAST.Then.Score.Value,
			Reason:  ruleAST.Then.Reason.Value,
		},
	}

	if ruleAST.When != nil {
		conditions, err := flattenLogicalExpression(ruleAST.When)
		if err != nil {
			return nil, fmt.Errorf("failed to flatten logical expression: %w", err)
		}

		for _, condExpr := range conditions {
			condJSON, err := expressionToCondition(condExpr)
			if err != nil {
				return nil, fmt.Errorf("failed to convert condition: %w", err)
			}

			jsonBytes, err := json.Marshal(condJSON)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal condition: %w", err)
			}

			rule.When = append(rule.When, json.RawMessage(jsonBytes))
		}
	}

	return rule, nil
}

func flattenLogicalExpression(expr Expression) ([]Expression, error) {
	switch e := expr.(type) {
	case *LogicalExpression:
		var conditions []Expression

		leftConditions, err := flattenLogicalExpression(e.Left)
		if err != nil {
			return nil, err
		}
		conditions = append(conditions, leftConditions...)

		rightConditions, err := flattenLogicalExpression(e.Right)
		if err != nil {
			return nil, err
		}
		conditions = append(conditions, rightConditions...)

		if e.Operator == "or" {
			return []Expression{e}, nil
		}

		return conditions, nil
	default:
		return []Expression{expr}, nil
	}
}

func expressionToCondition(expr Expression) (interface{}, error) {
	switch e := expr.(type) {
	case *InfixExpression:
		return infixToCondition(e)
	case *FunctionCall:
		return functionToCondition(e)
	case *LogicalExpression:
		return logicalToCondition(e)
	default:
		return nil, fmt.Errorf("unsupported expression type: %T", expr)
	}
}

func infixToCondition(expr *InfixExpression) (interface{}, error) {
	if funcCall, ok := expr.Left.(*FunctionCall); ok {
		op := mapOperatorFromToken(expr.Operator)
		if op == "" {
			return nil, fmt.Errorf("unsupported operator: %s", expr.Operator)
		}

		value, err := expressionToValue(expr.Right)
		if err != nil {
			return nil, fmt.Errorf("invalid value in condition: %w", err)
		}

		// Emit "aggregate" type so the interpreter recognizes sum/count/avg/max/min (it does not handle "function_comparison").
		if funcCall.Name == "sum" || funcCall.Name == "count" || funcCall.Name == "avg" || funcCall.Name == "max" || funcCall.Name == "min" {
			return functionCallToAggregateCondition(funcCall, op, value)
		}

		funcCondition, err := functionToCondition(funcCall)
		if err != nil {
			return nil, fmt.Errorf("failed to convert function call: %w", err)
		}

		return map[string]interface{}{
			"type":     "function_comparison",
			"function": funcCondition,
			"op":       op,
			"value":    value,
		}, nil
	}

	field, err := expressionToFieldPath(expr.Left)
	if err != nil {
		return nil, fmt.Errorf("invalid field in condition: %w", err)
	}

	op := mapOperatorFromToken(expr.Operator)
	if op == "" {
		return nil, fmt.Errorf("unsupported operator: %s", expr.Operator)
	}

	value, err := expressionToValue(expr.Right)
	if err != nil {
		return nil, fmt.Errorf("invalid value in condition: %w", err)
	}

	return SimpleCond{
		Field: field,
		Op:    op,
		Value: value,
	}, nil
}

// functionCallToAggregateCondition converts sum(...) / count(...) / avg(...) / max(...) / min(...) comparisons
// into the "aggregate" condition format that the interpreter expects (it does not handle "function_comparison").
func functionCallToAggregateCondition(funcCall *FunctionCall, op string, value interface{}) (interface{}, error) {
	if len(funcCall.Arguments) < 2 {
		return nil, fmt.Errorf("aggregate function %s requires 2 arguments (conditional, time_window)", funcCall.Name)
	}
	condExpr, ok := funcCall.Arguments[0].(*ConditionalExpression)
	if !ok {
		return nil, fmt.Errorf("first argument to %s must be a conditional (e.g. amount when source == $current.source)", funcCall.Name)
	}
	// sum/avg/max/min require a value (e.g. amount); count() can be count(when condition, "PT1H") with no value
	valueRequiringMetrics := map[string]bool{"sum": true, "avg": true, "max": true, "min": true}
	if valueRequiringMetrics[funcCall.Name] {
		if condExpr.Value == nil {
			return nil, fmt.Errorf("%s() conditional must have a value (e.g. amount when source == $current.source)", funcCall.Name)
		}
		_, err := expressionToFieldPath(condExpr.Value)
		if err != nil {
			return nil, fmt.Errorf("%s() value must be a field (e.g. amount): %w", funcCall.Name, err)
		}
	}
	filterCond, err := expressionToCondition(condExpr.Condition)
	if err != nil {
		return nil, fmt.Errorf("aggregate filter condition: %w", err)
	}
	filterSimple, ok := filterCond.(SimpleCond)
	if !ok {
		return nil, fmt.Errorf("aggregate filter must be a simple comparison (e.g. source == $current.source)")
	}
	timeWindowStr, ok := valueToString(funcCall.Arguments[1])
	if !ok || timeWindowStr == "" {
		return nil, fmt.Errorf("second argument to %s must be a time window string (e.g. PT1H)", funcCall.Name)
	}
	var valueNum float64
	switch v := value.(type) {
	case float64:
		valueNum = v
	case int:
		valueNum = float64(v)
	case int64:
		valueNum = float64(v)
	default:
		return nil, fmt.Errorf("aggregate comparison value must be numeric, got %T", value)
	}
	return map[string]interface{}{
		"type":        "aggregate",
		"metric":      funcCall.Name,
		"time_window": timeWindowStr,
		"op":          op,
		"value":       valueNum,
		"filter":      filterSimple,
	}, nil
}

func valueToString(expr Expression) (string, bool) {
	if lit, ok := expr.(*StringLiteral); ok {
		return lit.Value, true
	}
	return "", false
}

func functionToCondition(expr *FunctionCall) (interface{}, error) {
	funcName := expr.Name

	args := make(map[string]interface{})

	for i, arg := range expr.Arguments {
		if namedArg, ok := arg.(*NamedArgument); ok {
			value, err := expressionToValue(namedArg.Value)
			if err != nil {
				return nil, fmt.Errorf("failed to convert named argument %s: %w", namedArg.Name, err)
			}
			args[namedArg.Name] = value
		} else {
			value, err := expressionToValue(arg)
			if err != nil {
				return nil, fmt.Errorf("failed to convert argument %d: %w", i, err)
			}
			args[fmt.Sprintf("arg_%d", i)] = value
		}
	}

	return map[string]interface{}{
		"type":      "function",
		"function":  funcName,
		"arguments": args,
	}, nil
}

func logicalToCondition(expr *LogicalExpression) (interface{}, error) {
	leftCond, err := expressionToCondition(expr.Left)
	if err != nil {
		return nil, fmt.Errorf("failed to convert left condition: %w", err)
	}

	rightCond, err := expressionToCondition(expr.Right)
	if err != nil {
		return nil, fmt.Errorf("failed to convert right condition: %w", err)
	}

	return map[string]interface{}{
		"type":     "logical",
		"operator": expr.Operator,
		"left":     leftCond,
		"right":    rightCond,
	}, nil
}

func expressionToFieldPath(expr Expression) (string, error) {
	switch e := expr.(type) {
	case *Identifier:
		return e.Value, nil
	case *FieldPath:
		return strings.Join(e.Parts, "."), nil
	default:
		return "", fmt.Errorf("expected field path, got %T", expr)
	}
}

func expressionToValue(expr Expression) (interface{}, error) {
	switch e := expr.(type) {
	case *StringLiteral:
		return e.Value, nil
	case *NumberLiteral:
		return e.Value, nil
	case *BooleanLiteral:
		return e.Value, nil
	case *Variable:
		return "$" + e.Name, nil
	case *Identifier:
		return e.Value, nil
	case *FieldPath:
		return strings.Join(e.Parts, "."), nil
	case *ArrayLiteral:
		var values []interface{}
		for _, elem := range e.Elements {
			val, err := expressionToValue(elem)
			if err != nil {
				return nil, err
			}
			values = append(values, val)
		}
		return values, nil
	case *ObjectLiteral:
		obj := make(map[string]interface{})
		for key, valueExpr := range e.Pairs {
			val, err := expressionToValue(valueExpr)
			if err != nil {
				return nil, err
			}
			obj[key] = val
		}
		return obj, nil
	case *NamedArgument:
		val, err := expressionToValue(e.Value)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			e.Name: val,
		}, nil
	case *ConditionalExpression:
		var valueVal interface{}
		if e.Value != nil {
			var err error
			valueVal, err = expressionToValue(e.Value)
			if err != nil {
				return nil, err
			}
		} else {
			valueVal = nil
		}

		conditionVal, err := expressionToCondition(e.Condition)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"type":      "conditional",
			"value":     valueVal,
			"condition": conditionVal,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported value type: %T", expr)
	}
}

func mapOperatorFromToken(op string) string {
	switch op {
	case "==":
		return "eq"
	case "!=":
		return "ne"
	case ">":
		return "gt"
	case ">=":
		return "gte"
	case "<":
		return "lt"
	case "<=":
		return "lte"
	case "in":
		return "in"
	case "regex":
		return "regex"
	case "not_regex":
		return "not_regex"
	default:
		return ""
	}
}
