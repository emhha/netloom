package fingerprint

import "strings"

// Node is a single node in the rule expression AST. Leaf nodes perform O(1)
// lookups against a pre-filled MatchContext.Hits table; logical nodes combine
// the results of their children.
type Node interface {
	Match(ctx *MatchContext) bool
	// collectKeywords appends all literal keywords in this subtree into dst,
	// tagged with their Field. Used by ACIndex construction.
	collectKeywords(dst *[]fieldKeyword)
}

// fieldKeyword pairs a keyword with the Field it belongs to.
type fieldKeyword struct {
	field   Field
	keyword string
}

// BodyNode matches when ctx.Hits[FieldBody][Value] is true.
type BodyNode struct{ Value string }

func (n BodyNode) Match(ctx *MatchContext) bool {
	return ctx.Hits[FieldBody][n.Value]
}
func (n BodyNode) collectKeywords(dst *[]fieldKeyword) {
	*dst = append(*dst, fieldKeyword{FieldBody, n.Value})
}

// HeaderNode matches when the serialised header blob contains Value.
type HeaderNode struct{ Value string }

func (n HeaderNode) Match(ctx *MatchContext) bool {
	return ctx.Hits[FieldHeader][n.Value]
}
func (n HeaderNode) collectKeywords(dst *[]fieldKeyword) {
	*dst = append(*dst, fieldKeyword{FieldHeader, n.Value})
}

// TitleNode matches when ctx.Hits[FieldTitle][Value] is true.
type TitleNode struct{ Value string }

func (n TitleNode) Match(ctx *MatchContext) bool {
	return ctx.Hits[FieldTitle][n.Value]
}
func (n TitleNode) collectKeywords(dst *[]fieldKeyword) {
	*dst = append(*dst, fieldKeyword{FieldTitle, n.Value})
}

// ServerNode matches when ctx.Hits[FieldServer][Value] is true.
type ServerNode struct{ Value string }

func (n ServerNode) Match(ctx *MatchContext) bool {
	return ctx.Hits[FieldServer][n.Value]
}
func (n ServerNode) collectKeywords(dst *[]fieldKeyword) {
	*dst = append(*dst, fieldKeyword{FieldServer, n.Value})
}

// CertNode matches when resp.TLS.Subject contains Value (case-insensitive).
// It does NOT use the AC index because cert rules are rare and the Subject
// is only available from the TLS handshake, not pre-scannable.
type CertNode struct{ Value string }

func (n CertNode) Match(ctx *MatchContext) bool {
	if ctx.Response == nil || ctx.Response.TLS == nil {
		return false
	}
	return strings.Contains(
		strings.ToLower(ctx.Response.TLS.Subject),
		strings.ToLower(n.Value),
	)
}
func (n CertNode) collectKeywords(_ *[]fieldKeyword) {
	// cert nodes are not AC-indexed
}

// AndNode requires both Left and Right to match.
type AndNode struct{ Left, Right Node }

func (n AndNode) Match(ctx *MatchContext) bool {
	return n.Left.Match(ctx) && n.Right.Match(ctx)
}
func (n AndNode) collectKeywords(dst *[]fieldKeyword) {
	n.Left.collectKeywords(dst)
	n.Right.collectKeywords(dst)
}

// OrNode requires at least one of Left or Right to match.
type OrNode struct{ Left, Right Node }

func (n OrNode) Match(ctx *MatchContext) bool {
	return n.Left.Match(ctx) || n.Right.Match(ctx)
}
func (n OrNode) collectKeywords(dst *[]fieldKeyword) {
	n.Left.collectKeywords(dst)
	n.Right.collectKeywords(dst)
}

// NotNode inverts its Child's match result.
type NotNode struct{ Child Node }

func (n NotNode) Match(ctx *MatchContext) bool {
	return !n.Child.Match(ctx)
}
func (n NotNode) collectKeywords(dst *[]fieldKeyword) {
	n.Child.collectKeywords(dst)
}
