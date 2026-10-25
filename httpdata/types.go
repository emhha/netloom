// Package httpdata provides immutable HTTP snapshots for offline analysis.
package httpdata

import "net/http"

type Request struct {
	URL, Method string
	Header      http.Header
	Body        []byte
}
type TLSInfo struct{ Subject string }
type Response struct {
	// URL is the URL of this captured response, used to constrain probe paths.
	URL string
	// FaviconMD5 is the MD5 of an independently captured icon, never the page.
	FaviconMD5                    string
	StatusCode                    int
	Header                        http.Header
	Body                          []byte
	BodyTruncated                 bool
	ContentType, WebServer, Title string
	FaviconHash                   int32
	TLS                           *TLSInfo
}
type Artifact struct{ Type, Value string }
