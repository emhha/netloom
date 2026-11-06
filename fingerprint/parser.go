package fingerprint

import (
	"fmt"
)

// parser implements a recursive descent parser over the token stream produced
// by the lexer. The supported expression grammar is:
//
//	expr      = orExpr
//	orExpr    = andExpr { "||" andExpr }
//	andExpr   = unaryExpr { "&&" unaryExpr }
//	unaryExpr = "!" unaryExpr | factor
//	factor    = condition | "(" expr ")"
//	condition = field "=" string | field "!=" string
type parser struct {
	tokens []Token
	pos    int
}

func newParser(tokens []Token) *parser {
	return &parser{tokens: tokens}
}

func (p *parser) peek() Token {
	if p.pos >= len(p.tokens) {
		return Token{Type: tokEOF}
	}
	return p.tokens[p.pos]
}

func (p *parser) consume() Token {
	t := p.peek()
	p.pos++
	return t
}

// Parse parses the full token stream and returns the root AST node.
func (p *parser) Parse() (Node, error) {
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().Type != tokEOF {
		return nil, fmt.Errorf("parser: unexpected token %v at pos %d", p.peek().Type, p.pos)
	}
	return node, nil
}

func (p *parser) parseOr() (Node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek().Type == tokOr {
		p.consume()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = OrNode{Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (Node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.peek().Type == tokAnd {
		p.consume()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = AndNode{Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) parseUnary() (Node, error) {
	if p.peek().Type == tokNot {
		p.consume()
		child, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return NotNode{Child: child}, nil
	}
	return p.parseFactor()
}

func (p *parser) parseFactor() (Node, error) {
	if p.peek().Type == tokLParen {
		p.consume()
		node, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek().Type != tokRParen {
			return nil, fmt.Errorf("parser: expected ')' at pos %d", p.pos)
		}
		p.consume()
		return node, nil
	}
	return p.parseCondition()
}

// isFieldToken reports whether a token type represents a field name.
func isFieldToken(tt TokenType) bool {
	switch tt {
	case tokBody, tokHeader, tokTitle, tokServer, tokCert:
		return true
	}
	return false
}

// parseCondition parses:  field "=" string  |  field "!=" string
// Note: the lexer already emitted separate field + eq/neq + string tokens when
// scanning field expressions. After a field token the next is tokEq or tokNeq,
// followed by a tokString.
func (p *parser) parseCondition() (Node, error) {
	ft := p.peek()
	if !isFieldToken(ft.Type) {
		return nil, fmt.Errorf("parser: expected field token at pos %d, got %v", p.pos, ft.Type)
	}
	p.consume()

	op := p.peek()
	if op.Type != tokEq && op.Type != tokNeq {
		return nil, fmt.Errorf("parser: expected = or != at pos %d, got %v", p.pos, op.Type)
	}
	p.consume()

	str := p.peek()
	if str.Type != tokString {
		return nil, fmt.Errorf("parser: expected string literal at pos %d, got %v", p.pos, str.Type)
	}
	p.consume()

	leaf := buildLeaf(ft.Type, str.Value)

	if op.Type == tokNeq {
		// field!="value"  ≡  NotNode{Child: leafNode}
		return NotNode{Child: leaf}, nil
	}
	return leaf, nil
}

// buildLeaf constructs the appropriate typed leaf node for a field token.
func buildLeaf(tt TokenType, value string) Node {
	switch tt {
	case tokHeader:
		return HeaderNode{Value: value}
	case tokTitle:
		return TitleNode{Value: value}
	case tokServer:
		return ServerNode{Value: value}
	case tokCert:
		return CertNode{Value: value}
	default:
		return BodyNode{Value: value}
	}
}

// parseRule is the top-level entry: lex + parse a single rule expression.
// Returns (nil, nil) for icon_hash rules; these are extracted by the caller.
func parseRule(expr string) (Node, bool, string, error) {
	l := newLexer(expr)
	tokens, err := l.Tokenize()
	if err != nil {
		return nil, false, "", fmt.Errorf("parseRule: %w", err)
	}

	// Detect icon_hash-only rule (single condition, field "icon_hash").
	if isIconHashRule(tokens) {
		val := iconHashValue(tokens)
		return nil, true, val, nil
	}

	p := newParser(tokens)
	node, err := p.Parse()
	if err != nil {
		return nil, false, "", fmt.Errorf("parseRule: %w", err)
	}
	return node, false, "", nil
}

// isIconHashRule checks if the token stream is a single icon_hash condition.
// icon_hash rules are handled by the lexer returning tokBody for the field type
// but the original text started with "icon_hash"; we detect by checking the
// raw input is captured in the lexer — instead we check the token pattern.
// Because the lexer maps icon_hash field to tokBody but stores the field name
// in Value, we need a different approach.
//
// Since the lexer already returns the raw field string in Token.Value for field
// tokens (see readField), and sets type to tokBody as a placeholder, icon_hash
// detection uses the Value == "icon_hash" check.
func isIconHashRule(tokens []Token) bool {
	// Expected pattern: [field(Value="icon_hash"), tokEq, tokString, tokEOF]
	if len(tokens) == 4 &&
		tokens[0].Type == tokBody && tokens[0].Value == "icon_hash" &&
		tokens[1].Type == tokEq &&
		tokens[2].Type == tokString &&
		tokens[3].Type == tokEOF {
		return true
	}
	return false
}

func iconHashValue(tokens []Token) string {
	if len(tokens) >= 3 {
		return tokens[2].Value
	}
	return ""
}
