package fingerprint

import (
	"fmt"
	"strings"
)

// TokenType identifies the class of a lexical token in a webfinger rule
// expression.
type TokenType int

const (
	tokEOF    TokenType = iota
	tokBody             // body
	tokHeader           // header
	tokTitle            // title
	tokServer           // server
	tokCert             // cert
	tokString           // "keyword"
	tokAnd              // &&
	tokOr               // ||
	tokNot              // ! (standalone prefix)
	tokLParen           // (
	tokRParen           // )
	tokEq               // = (used internally by lexer)
	tokNeq              // != (field!="value")
)

// Token is a single lexical unit.
type Token struct {
	Type  TokenType
	Value string // set for tokString tokens
}

// lexer tokenises a single webfinger rule expression string.
type lexer struct {
	input []rune
	pos   int
}

func newLexer(input string) *lexer {
	return &lexer{input: []rune(strings.TrimSpace(input))}
}

func (l *lexer) peek() (rune, bool) {
	if l.pos >= len(l.input) {
		return 0, false
	}
	return l.input[l.pos], true
}

func (l *lexer) advance() {
	l.pos++
}

func (l *lexer) skipSpaces() {
	for l.pos < len(l.input) && (l.input[l.pos] == ' ' || l.input[l.pos] == '\t') {
		l.pos++
	}
}

// Tokenize converts the entire input to a token slice, returning an error on
// unrecognised input.
func (l *lexer) Tokenize() ([]Token, error) {
	var tokens []Token
	for {
		l.skipSpaces()
		ch, ok := l.peek()
		if !ok {
			tokens = append(tokens, Token{Type: tokEOF})
			break
		}

		switch {
		case ch == '(':
			l.advance()
			tokens = append(tokens, Token{Type: tokLParen})

		case ch == ')':
			l.advance()
			tokens = append(tokens, Token{Type: tokRParen})

		case ch == '&':
			l.advance()
			ch2, ok2 := l.peek()
			if !ok2 || ch2 != '&' {
				return nil, fmt.Errorf("lexer: expected && at pos %d", l.pos)
			}
			l.advance()
			tokens = append(tokens, Token{Type: tokAnd})

		case ch == '|':
			l.advance()
			ch2, ok2 := l.peek()
			if !ok2 || ch2 != '|' {
				return nil, fmt.Errorf("lexer: expected || at pos %d", l.pos)
			}
			l.advance()
			tokens = append(tokens, Token{Type: tokOr})

		case ch == '!':
			l.advance()
			ch2, ok2 := l.peek()
			if ok2 && ch2 == '=' {
				// != as standalone token — handled in parser as field!="value"
				// Actually !=  appears as: header!="abc", so it's part of a condition.
				// We emit tokNeq and let the parser handle it.
				l.advance()
				tokens = append(tokens, Token{Type: tokNeq})
			} else {
				tokens = append(tokens, Token{Type: tokNot})
			}

		case isFieldStart(ch):
			field, tokType, err := l.readField()
			if err != nil {
				return nil, err
			}
			l.skipSpaces()

			// Determine whether next char is = or !=
			nextCh, nextOk := l.peek()
			if !nextOk {
				return nil, fmt.Errorf("lexer: unexpected end after field %q", field)
			}

			if nextCh == '!' {
				// field!="value"
				l.advance()
				eqCh, eqOk := l.peek()
				if !eqOk || eqCh != '=' {
					return nil, fmt.Errorf("lexer: expected = after ! in field!= at pos %d", l.pos)
				}
				l.advance()
				// Emit: field, !=, string
				tokens = append(tokens, Token{Type: tokType, Value: field})
				tokens = append(tokens, Token{Type: tokNeq})
			} else if nextCh == '=' {
				l.advance()
				tokens = append(tokens, Token{Type: tokType, Value: field})
				tokens = append(tokens, Token{Type: tokEq})
			} else {
				return nil, fmt.Errorf("lexer: expected = or != after field %q at pos %d", field, l.pos)
			}

			l.skipSpaces()
			str, err := l.readQuotedString()
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, Token{Type: tokString, Value: str})

		default:
			return nil, fmt.Errorf("lexer: unexpected character %q at pos %d", ch, l.pos)
		}
	}
	return tokens, nil
}

// readField reads a field name (body/header/title/server/cert/icon_hash).
func (l *lexer) readField() (string, TokenType, error) {
	start := l.pos
	for l.pos < len(l.input) {
		ch := l.input[l.pos]
		if ch == '=' || ch == '!' || ch == ' ' || ch == '\t' || ch == '(' || ch == ')' {
			break
		}
		l.pos++
	}
	field := string(l.input[start:l.pos])
	switch field {
	case "body":
		return field, tokBody, nil
	case "header":
		return field, tokHeader, nil
	case "title":
		return field, tokTitle, nil
	case "server":
		return field, tokServer, nil
	case "cert":
		return field, tokCert, nil
	case "icon_hash":
		// icon_hash is not a regular AST field; caller handles separately.
		return field, tokBody, nil // placeholder, compiler will strip it
	default:
		return field, tokBody, fmt.Errorf("lexer: unknown field %q", field)
	}
}

// readQuotedString reads a "..." string literal.
func (l *lexer) readQuotedString() (string, error) {
	ch, ok := l.peek()
	if !ok || ch != '"' {
		return "", fmt.Errorf("lexer: expected '\"' at pos %d", l.pos)
	}
	l.advance()

	var buf []rune
	for {
		ch, ok := l.peek()
		if !ok {
			return "", fmt.Errorf("lexer: unterminated string at pos %d", l.pos)
		}
		l.advance()
		if ch == '"' {
			break
		}
		if ch == '\\' {
			next, ok2 := l.peek()
			if !ok2 {
				return "", fmt.Errorf("lexer: trailing backslash at pos %d", l.pos)
			}
			l.advance()
			buf = append(buf, next)
			continue
		}
		buf = append(buf, ch)
	}
	return string(buf), nil
}

func isFieldStart(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') || ch == '_'
}
