// Package netloomdata copies runtime results into offline analysis snapshots.
// Import httpdata directly when no runtime conversion is needed.
package netloomdata

import (
	"github.com/emhha/netloom"
	"github.com/emhha/netloom/httpdata"
	"net/http"
)

func Request(in *netloom.Request) *httpdata.Request {
	if in == nil {
		return nil
	}
	return &httpdata.Request{URL: in.URL, Method: in.Method, Header: http.Header(in.Header).Clone(), Body: append([]byte(nil), in.Body...)}
}

func Response(in *netloom.Response) *httpdata.Response {
	if in == nil {
		return nil
	}
	out := &httpdata.Response{StatusCode: in.StatusCode, Header: http.Header(in.Header).Clone(), Body: append([]byte(nil), in.Body...), BodyTruncated: in.BodyTruncated, ContentType: in.ContentType, WebServer: in.WebServer, Title: in.Title, FaviconHash: in.FaviconHash}
	if in.TLS != nil {
		out.TLS = &httpdata.TLSInfo{Subject: in.TLS.Subject}
	}
	return out
}
