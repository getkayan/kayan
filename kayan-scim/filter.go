package scim

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// Comparison operators (RFC 7644 section 3.4.2.2).
const (
	OpEqual              = "eq"
	OpNotEqual           = "ne"
	OpContains           = "co"
	OpStartsWith         = "sw"
	OpEndsWith           = "ew"
	OpPresent            = "pr"
	OpGreaterThan        = "gt"
	OpGreaterThanOrEqual = "ge"
	OpLessThan           = "lt"
	OpLessThanOrEqual    = "le"
)

// FilterExpr is a node in a parsed SCIM filter.
//
// The filter is parsed to a tree rather than to backend-specific query text,
// so it stays independent of both transport and storage: a GORM adapter walks
// it into a WHERE clause, a Mongo adapter into a BSON document, and neither
// needs a parser of its own.
type FilterExpr interface {
	// String renders the expression back to SCIM filter syntax.
	String() string

	filterNode()
}

// Comparison compares an attribute against a value, or tests its presence.
type Comparison struct {
	Path     Path
	Operator string
	// Value is nil for the "pr" (present) operator, which takes no operand.
	Value any
}

func (Comparison) filterNode() {}

// String implements [FilterExpr].
func (c Comparison) String() string {
	if c.Operator == OpPresent {
		return c.Path.String() + " pr"
	}
	return fmt.Sprintf("%s %s %s", c.Path.String(), c.Operator, formatValue(c.Value))
}

// And is a conjunction.
type And struct{ Left, Right FilterExpr }

func (And) filterNode() {}

// String implements [FilterExpr].
func (a And) String() string { return "(" + a.Left.String() + " and " + a.Right.String() + ")" }

// Or is a disjunction.
type Or struct{ Left, Right FilterExpr }

func (Or) filterNode() {}

// String implements [FilterExpr].
func (o Or) String() string { return "(" + o.Left.String() + " or " + o.Right.String() + ")" }

// Not negates an expression.
type Not struct{ Expr FilterExpr }

func (Not) filterNode() {}

// String implements [FilterExpr].
func (n Not) String() string { return "not (" + n.Expr.String() + ")" }

// MaxFilterDepth bounds nesting in a filter.
//
// The filter arrives as a query parameter, so a deeply nested expression would
// otherwise be a cheap way to exhaust the stack.
const MaxFilterDepth = 20

// ParseFilter parses a SCIM filter expression (RFC 7644 section 3.4.2.2).
//
//	userName eq "bjensen"
//	name.familyName co "O'Malley"
//	emails[type eq "work" and value co "@example.com"]
//	title pr and userType eq "Employee"
//	not (userType eq "Employee")
func ParseFilter(filter string) (FilterExpr, error) {
	tokens, err := tokenizeFilter(filter)
	if err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return nil, NewError("400", "invalidFilter", "empty filter")
	}

	p := &filterParser{tokens: tokens}
	expr, err := p.parseOr(0)
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.tokens) {
		return nil, NewError("400", "invalidFilter",
			fmt.Sprintf("unexpected %q at position %d", p.tokens[p.pos].text, p.pos))
	}
	return expr, nil
}

// --- tokenizer ---

type tokenKind int

const (
	tokenWord tokenKind = iota
	tokenString
	tokenNumber
	tokenLParen
	tokenRParen
)

type filterToken struct {
	kind tokenKind
	text string
}

func tokenizeFilter(input string) ([]filterToken, error) {
	var tokens []filterToken
	runes := []rune(input)

	for i := 0; i < len(runes); {
		switch c := runes[i]; {
		case unicode.IsSpace(c):
			i++

		case c == '(':
			tokens = append(tokens, filterToken{kind: tokenLParen, text: "("})
			i++

		case c == ')':
			tokens = append(tokens, filterToken{kind: tokenRParen, text: ")"})
			i++

		case c == '"':
			// A quoted string, with JSON escape semantics.
			var b strings.Builder
			i++
			closed := false
			for i < len(runes) {
				if runes[i] == '\\' && i+1 < len(runes) {
					switch runes[i+1] {
					case '"', '\\', '/':
						b.WriteRune(runes[i+1])
					case 'n':
						b.WriteByte('\n')
					case 't':
						b.WriteByte('\t')
					case 'r':
						b.WriteByte('\r')
					case 'b':
						b.WriteByte('\b')
					case 'f':
						b.WriteByte('\f')
					case 'u':
						// \uXXXX, which is how JSON encodes a control
						// character. Rendering a filter produces these, so the
						// tokenizer must accept them or a filter cannot survive
						// a round trip.
						if i+6 > len(runes) {
							return nil, NewError("400", "invalidFilter", "truncated \\u escape")
						}
						code, err := strconv.ParseUint(string(runes[i+2:i+6]), 16, 32)
						if err != nil {
							return nil, NewError("400", "invalidFilter", "malformed \\u escape")
						}
						b.WriteRune(rune(code))
						i += 6
						continue
					default:
						return nil, NewError("400", "invalidFilter",
							fmt.Sprintf("invalid escape sequence \\%c", runes[i+1]))
					}
					i += 2
					continue
				}
				if runes[i] == '"' {
					i++
					closed = true
					break
				}
				b.WriteRune(runes[i])
				i++
			}
			if !closed {
				return nil, NewError("400", "invalidFilter", "unterminated string")
			}
			tokens = append(tokens, filterToken{kind: tokenString, text: b.String()})

		case c == '[' || c == ']':
			// Brackets belong to a path, which is tokenized as one word.
			return nil, NewError("400", "invalidFilter", "nested value filters are not supported")

		default:
			start := i
			for i < len(runes) && !unicode.IsSpace(runes[i]) && runes[i] != '(' && runes[i] != ')' {
				i++
			}
			word := string(runes[start:i])
			kind := tokenWord
			if isNumeric(word) {
				kind = tokenNumber
			}
			tokens = append(tokens, filterToken{kind: kind, text: word})
		}
	}

	return tokens, nil
}

func isNumeric(word string) bool {
	if word == "" {
		return false
	}
	_, err := strconv.ParseFloat(word, 64)
	return err == nil
}

// --- parser ---

type filterParser struct {
	tokens []filterToken
	pos    int
}

func (p *filterParser) peek() (filterToken, bool) {
	if p.pos >= len(p.tokens) {
		return filterToken{}, false
	}
	return p.tokens[p.pos], true
}

// parseOr handles the lowest-precedence operator.
func (p *filterParser) parseOr(depth int) (FilterExpr, error) {
	if depth > MaxFilterDepth {
		return nil, NewError("400", "tooMany", "filter is nested too deeply")
	}

	left, err := p.parseAnd(depth + 1)
	if err != nil {
		return nil, err
	}

	for {
		token, ok := p.peek()
		if !ok || !strings.EqualFold(token.text, "or") {
			return left, nil
		}
		p.pos++

		right, err := p.parseAnd(depth + 1)
		if err != nil {
			return nil, err
		}
		left = Or{Left: left, Right: right}
	}
}

func (p *filterParser) parseAnd(depth int) (FilterExpr, error) {
	if depth > MaxFilterDepth {
		return nil, NewError("400", "tooMany", "filter is nested too deeply")
	}

	left, err := p.parseUnary(depth + 1)
	if err != nil {
		return nil, err
	}

	for {
		token, ok := p.peek()
		if !ok || !strings.EqualFold(token.text, "and") {
			return left, nil
		}
		p.pos++

		right, err := p.parseUnary(depth + 1)
		if err != nil {
			return nil, err
		}
		left = And{Left: left, Right: right}
	}
}

func (p *filterParser) parseUnary(depth int) (FilterExpr, error) {
	if depth > MaxFilterDepth {
		return nil, NewError("400", "tooMany", "filter is nested too deeply")
	}

	token, ok := p.peek()
	if !ok {
		return nil, NewError("400", "invalidFilter", "unexpected end of filter")
	}

	if token.kind == tokenWord && strings.EqualFold(token.text, "not") {
		p.pos++
		inner, err := p.parseUnary(depth + 1)
		if err != nil {
			return nil, err
		}
		return Not{Expr: inner}, nil
	}

	if token.kind == tokenLParen {
		p.pos++
		inner, err := p.parseOr(depth + 1)
		if err != nil {
			return nil, err
		}
		next, ok := p.peek()
		if !ok || next.kind != tokenRParen {
			return nil, NewError("400", "invalidFilter", "missing closing parenthesis")
		}
		p.pos++
		return inner, nil
	}

	return p.parseComparison()
}

func (p *filterParser) parseComparison() (FilterExpr, error) {
	attribute, ok := p.peek()
	if !ok || attribute.kind != tokenWord {
		return nil, NewError("400", "invalidFilter", "expected an attribute name")
	}
	p.pos++

	path, err := ParsePath(attribute.text)
	if err != nil {
		return nil, err
	}

	operator, ok := p.peek()
	if !ok {
		return nil, NewError("400", "invalidFilter",
			fmt.Sprintf("expected an operator after %q", attribute.text))
	}
	p.pos++

	op := strings.ToLower(operator.text)
	switch op {
	case OpPresent:
		return Comparison{Path: path, Operator: OpPresent}, nil

	case OpEqual, OpNotEqual, OpContains, OpStartsWith, OpEndsWith,
		OpGreaterThan, OpGreaterThanOrEqual, OpLessThan, OpLessThanOrEqual:
		// handled below

	default:
		return nil, NewError("400", "invalidFilter", fmt.Sprintf("unknown operator %q", operator.text))
	}

	value, ok := p.peek()
	if !ok {
		return nil, NewError("400", "invalidFilter", fmt.Sprintf("expected a value after %q", op))
	}
	p.pos++

	return Comparison{Path: path, Operator: op, Value: literalValue(value)}, nil
}

// literalValue converts a token to its Go value.
func literalValue(token filterToken) any {
	switch token.kind {
	case tokenString:
		return token.text
	case tokenNumber:
		if i, err := strconv.ParseInt(token.text, 10, 64); err == nil {
			return i
		}
		if f, err := strconv.ParseFloat(token.text, 64); err == nil {
			return f
		}
		return token.text
	default:
		switch strings.ToLower(token.text) {
		case "true":
			return true
		case "false":
			return false
		case "null":
			return nil
		}
		return token.text
	}
}

func formatValue(value any) string {
	switch v := value.(type) {
	case nil:
		return "null"
	case string:
		// json.Marshal rather than strconv.Quote: Quote emits Go escapes such
		// as \x7f, which are not valid in a SCIM filter, so the rendered
		// filter would not parse back through this same package.
		encoded, err := json.Marshal(v)
		if err != nil {
			return strconv.Quote(v)
		}
		return string(encoded)
	case bool:
		return strconv.FormatBool(v)
	default:
		return fmt.Sprintf("%v", v)
	}
}
