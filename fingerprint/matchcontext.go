package fingerprint

import (
	"strings"

	"github.com/emhha/netloom/httpdata"
)

// NewMatchContext builds a MatchContext from a httpdata.Response and a compiled
// ACIndex. It runs one AC scan per field and populates Hits so that subsequent
// AST leaf-node Match calls are O(1) lookups.
//
// BodyUTF8 is the UTF-8 decoded body (GBK/GB2312 sites are converted).
// HeaderBlob is the serialised lowercase-key header byte string used for AC.
func NewMatchContext(resp *httpdata.Response, idx *ACIndex) *MatchContext {
	ctx := &MatchContext{
		Response: resp,
		Hits:     make(map[Field]map[string]bool),
	}

	if resp == nil {
		return ctx
	}

	ctx.BodyUTF8 = decodeBodyToUTF8(resp)
	ctx.HeaderBlob = serializeHeader(resp.Header)

	populateACHits(ctx, idx)
	return ctx
}

// populateACHits scans already decoded fields without repeating preparation.
func populateACHits(ctx *MatchContext, idx *ACIndex) {
	if idx == nil {
		return
	}

	if idx.BodyAC != nil {
		ctx.Hits[FieldBody] = idx.BodyAC.Match(ctx.BodyUTF8)
	}
	if idx.HeaderAC != nil {
		ctx.Hits[FieldHeader] = idx.HeaderAC.Match(ctx.HeaderBlob)
	}
	if idx.TitleAC != nil && ctx.Response.Title != "" {
		ctx.Hits[FieldTitle] = idx.TitleAC.MatchString(ctx.Response.Title)
	}
	if idx.ServerAC != nil && ctx.Response.WebServer != "" {
		ctx.Hits[FieldServer] = idx.ServerAC.MatchString(ctx.Response.WebServer)
	}

}

// serializeHeader converts http.Header to a flat byte blob for AC scanning.
// Each header appears as "lowercase-key: value\n". HTTP/2 already lowercases
// keys; HTTP/1.1 headers may have mixed case — lower-casing here ensures
// consistent matching regardless of transport version.
func serializeHeader(h map[string][]string) []byte {
	if len(h) == 0 {
		return nil
	}
	var sb strings.Builder
	for k, vals := range h {
		lk := strings.ToLower(k)
		for _, v := range vals {
			sb.WriteString(lk)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteByte('\n')
		}
	}
	return []byte(sb.String())
}
