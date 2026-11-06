package nethttp

import (
	"bytes"
	"encoding/base64"
	"mime"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"errors"
	http "github.com/bogdanfinn/fhttp"
	"github.com/emhha/netloom"
)

type NameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type MultipartPart struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Filename    string `json:"filename,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Encoding    string `json:"encoding,omitempty"`
}

type BasicCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func token(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c) {
			continue
		}
		return false
	}
	return true
}

func BuildRequest(in RequestInput) (*netloom.Request, error) {
	u, err := netloom.HTTPURL(in.URL)
	if err != nil {
		return nil, errors.New(err.Error())
	}
	if len(in.URL) > 8192 || len(in.Headers)+len(in.HeaderValues) > 64 || len(in.Query) > 128 || len(in.Form) > 128 || len(in.Multipart) > 64 {
		return nil, errors.New("请求输入超过上限")
	}
	for _, pair := range in.Query {
		if u.RawQuery != "" {
			u.RawQuery += "&"
		}
		u.RawQuery += url.QueryEscape(pair.Name) + "=" + url.QueryEscape(pair.Value)
	}
	u.Fragment, u.RawFragment = "", ""
	if len(u.String()) > 8192 {
		return nil, errors.New("URL 不能超过 8192 字节")
	}
	headers := make(http.Header)
	headerBytes := 0
	add := func(name string, values []string) error {
		key := http.CanonicalHeaderKey(name)
		if !token(name) || len(values) == 0 || len(values) > 32 {
			return errors.New("请求头名称或值数量无效")
		}
		if _, exists := headers[key]; exists {
			return errors.New("同名请求头请通过 header_values 一次性传入多个值")
		}
		for _, value := range values {
			headerBytes += len(name) + len(value)
			for _, c := range value {
				if c == '\r' || c == '\n' || c == 0 || c < 32 && c != '\t' || c == 127 {
					return errors.New("请求头不能包含控制字符")
				}
			}
		}
		if headerBytes > 64<<10 {
			return errors.New("请求头总长度不能超过 64KB")
		}
		headers[key] = append([]string(nil), values...)
		return nil
	}
	for name, value := range in.Headers {
		if err := add(name, []string{value}); err != nil {
			return nil, err
		}
	}
	for name, values := range in.HeaderValues {
		if err := add(name, values); err != nil {
			return nil, err
		}
	}
	if values := headers.Values("Host"); len(values) > 0 && (len(values) != 1 || !strings.EqualFold(values[0], u.Host)) {
		return nil, errors.New("Host 请求头必须与 URL 一致")
	}
	for _, key := range []string{"Transfer-Encoding", "Proxy-Authorization", "Connection", "Upgrade", "Trailer"} {
		if len(headers.Values(key)) > 0 {
			return nil, errors.New("不支持手动设置请求头: " + key)
		}
	}
	method := strings.ToUpper(in.Method)
	if method == "" {
		method = "GET"
	}
	if !token(method) || len(method) > 32 || method == "CONNECT" {
		return nil, errors.New("HTTP 方法无效或不支持 CONNECT")
	}
	body, err := requestBody(in, headers)
	if err != nil {
		return nil, err
	}
	if values := headers.Values("Content-Length"); len(values) > 0 {
		if len(values) != 1 || values[0] != strconv.Itoa(len(body)) {
			return nil, errors.New("Content-Length 与实际请求体长度不一致")
		}
		headers.Del("Content-Length")
	}
	if in.BasicAuth != nil {
		if len(in.BasicAuth.Username)+len(in.BasicAuth.Password) > 8192 {
			return nil, errors.New("Basic Auth 凭据超过 8KB")
		}
		if headers.Get("Authorization") != "" || strings.Contains(in.BasicAuth.Username, ":") {
			return nil, errors.New("basic_auth 与 Authorization 冲突或用户名包含冒号")
		}
		headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(in.BasicAuth.Username+":"+in.BasicAuth.Password)))
	}
	if in.HTTPVersion != "" && in.HTTPVersion != "auto" && in.HTTPVersion != "1.1" {
		return nil, errors.New("http_version 支持 auto 或 1.1")
	}
	if !netloom.KnownProfile(in.TLSProfile) {
		return nil, errors.New("未知 TLS 指纹配置")
	}
	return &netloom.Request{Method: method, URL: u.String(), Header: headers, Body: body, HTTPVersion: in.HTTPVersion,
		Profile: netloom.ProfileByName(in.TLSProfile), VerifyTLS: !in.InsecureTLS, Timeout: time.Duration(in.TimeoutSeconds) * time.Second}, nil
}

func requestBody(in RequestInput, headers http.Header) ([]byte, error) {
	count := 0
	if in.Body != "" || in.BodyEncoding != "" {
		count++
	}
	if in.Form != nil {
		count++
	}
	if in.Multipart != nil {
		count++
	}
	if count > 1 {
		return nil, errors.New("body、form 和 multipart 只能选择一种")
	}
	body, err := decodeRequestBody(in.Body, in.BodyEncoding)
	if err != nil {
		return nil, err
	}
	if in.Form != nil {
		values := url.Values{}
		for _, pair := range in.Form {
			values.Add(pair.Name, pair.Value)
		}
		body = []byte(values.Encode())
		if headers.Get("Content-Type") == "" {
			headers.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	if in.Multipart != nil {
		if headers.Get("Content-Type") != "" {
			return nil, errors.New("multipart 会自动生成 Content-Type 和 boundary")
		}
		var buffer bytes.Buffer
		writer := multipart.NewWriter(&buffer)
		for _, part := range in.Multipart {
			if part.Name == "" || len(part.Name) > 256 || len(part.Filename) > 512 || strings.ContainsAny(part.Name+part.Filename+part.ContentType, "\r\n\x00") {
				return nil, errors.New("multipart 字段名称、文件名或内容类型无效")
			}
			data, err := decodeRequestBody(part.Value, part.Encoding)
			if err != nil {
				return nil, err
			}
			header := textproto.MIMEHeader{}
			params := map[string]string{"name": part.Name}
			if part.Filename != "" {
				params["filename"] = part.Filename
			}
			header.Set("Content-Disposition", mime.FormatMediaType("form-data", params))
			if part.ContentType != "" {
				if _, _, err := mime.ParseMediaType(part.ContentType); err != nil {
					return nil, errors.New("multipart 内容类型无效")
				}
				header.Set("Content-Type", part.ContentType)
			} else if part.Filename != "" {
				header.Set("Content-Type", "application/octet-stream")
			}
			w, err := writer.CreatePart(header)
			if err != nil {
				return nil, err
			}
			if _, err := w.Write(data); err != nil {
				return nil, err
			}
			if buffer.Len() > 256<<10 {
				return nil, errors.New("请求体不能超过 256KB")
			}
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
		body = buffer.Bytes()
		headers.Set("Content-Type", writer.FormDataContentType())
	}
	if len(body) > 256<<10 {
		return nil, errors.New("请求体不能超过 256KB")
	}
	return body, nil
}

func decodeRequestBody(value, encoding string) ([]byte, error) {
	if len(value) > 4*(256<<10)/3+4 {
		return nil, errors.New("请求体编码超过上限")
	}
	switch encoding {
	case "", "utf8":
		if !utf8.ValidString(value) {
			return nil, errors.New("UTF-8 请求体无效")
		}
		return []byte(value), nil
	case "base64":
		data, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil {
			return nil, errors.New("请求体 Base64 编码无效")
		}
		if len(data) > 256<<10 {
			return nil, errors.New("请求体不能超过 256KB")
		}
		return data, nil
	default:
		return nil, errors.New("body_encoding 支持 utf8 或 base64")
	}
}
