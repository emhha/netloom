package nethttp

import (
	"errors"
	"fmt"
	"math"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// ParseCurl imports a bounded HTTP curl command. It never invokes a shell,
// expands variables, reads files or accepts a second command/URL.
func ParseCurl(command string) (RequestInput, error) {
	var in RequestInput
	if len(command) > 512<<10 {
		return in, errors.New("curl command exceeds 512 KiB")
	}
	args, err := curlWords(command)
	if err != nil {
		return in, err
	}
	if len(args) == 0 || args[0] != "curl" && args[0] != "curl.exe" {
		return in, errors.New("command must begin with curl")
	}
	in.HeaderValues = map[string][]string{}
	var data []string
	compressed := false
	jsonData := false
	otherData := false
	explicitMethod := ""
	get := false
	form := false
	addHeader := func(raw string) error {
		i := strings.IndexByte(raw, ':')
		if i < 1 {
			return errors.New("curl header must use Name: Value")
		}
		name := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(raw[:i]))
		in.HeaderValues[name] = append(in.HeaderValues[name], strings.TrimSpace(raw[i+1:]))
		return nil
	}
	setURL := func(raw string) error {
		if in.URL != "" {
			return errors.New("only one curl URL is supported")
		}
		in.URL = raw
		return nil
	}
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			for _, u := range args[i+1:] {
				if err = setURL(u); err != nil {
					return in, err
				}
			}
			break
		}
		if !strings.HasPrefix(arg, "-") {
			if err = setURL(arg); err != nil {
				return in, err
			}
			continue
		}
		if !strings.HasPrefix(arg, "--") && len(arg) > 2 && strings.Trim(arg[1:], "sSLkIGN") == "" {
			for _, flag := range arg[1:] {
				switch flag {
				case 'L':
					in.FollowRedirects = true
				case 'k':
					in.InsecureTLS = true
				case 'I':
					explicitMethod = "HEAD"
				case 'G':
					get = true
				case 'N':
					in.Stream = true
				}
			}
			continue
		}
		value := ""
		hasValue := false
		if strings.HasPrefix(arg, "--") {
			if at := strings.IndexByte(arg, '='); at > 0 {
				value = arg[at+1:]
				arg = arg[:at]
				hasValue = true
			}
		} else if len(arg) > 2 && strings.Contains("XHdubFmAer", string(arg[1])) {
			value = arg[2:]
			arg = arg[:2]
			hasValue = true
		}
		next := func() (string, error) {
			if hasValue {
				return value, nil
			}
			i++
			if i >= len(args) {
				return "", fmt.Errorf("curl %s requires a value", arg)
			}
			return args[i], nil
		}
		switch arg {
		case "-L", "--location":
			in.FollowRedirects = true
		case "-k", "--insecure":
			in.InsecureTLS = true
		case "-I", "--head":
			explicitMethod = "HEAD"
		case "-G", "--get":
			get = true
		case "-N", "--no-buffer":
			in.Stream = true
		case "-s", "-S", "-sS", "-Ss", "--silent", "--show-error":
		case "--compressed":
			compressed = true
		case "--http1.1":
			in.HTTPVersion = "1.1"
		case "--url":
			v, e := next()
			if e != nil {
				return in, e
			}
			if err = setURL(v); err != nil {
				return in, err
			}
		case "-A", "--user-agent", "-e", "--referer", "-r", "--range":
			v, e := next()
			if e != nil {
				return in, e
			}
			name := "User-Agent"
			if arg == "-e" || arg == "--referer" {
				name = "Referer"
			}
			if arg == "-r" || arg == "--range" {
				name = "Range"
				v = "bytes=" + v
			}
			in.HeaderValues[name] = []string{v}
		case "-X", "--request":
			v, e := next()
			if e != nil {
				return in, e
			}
			explicitMethod = v
		case "-H", "--header":
			v, e := next()
			if e != nil {
				return in, e
			}
			if err = addHeader(v); err != nil {
				return in, err
			}
		case "-u", "--user":
			v, e := next()
			if e != nil {
				return in, e
			}
			name, password, ok := strings.Cut(v, ":")
			if !ok {
				return in, errors.New("curl --user requires user:password; interactive passwords are unsupported")
			}
			in.BasicAuth = &BasicCredentials{name, password}
		case "-b", "--cookie":
			v, e := next()
			if e != nil {
				return in, e
			}
			if !strings.Contains(v, "=") || strings.HasPrefix(v, "@") {
				return in, errors.New("cookie files are unsupported; use a Cookie session or literal cookie")
			}
			in.HeaderValues["Cookie"] = []string{v}
		case "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--json":
			v, e := next()
			if e != nil {
				return in, e
			}
			if strings.HasPrefix(v, "@") && arg != "--data-raw" {
				return in, errors.New("curl file reads are unsupported; supply literal data")
			}
			if arg == "--data-urlencode" {
				name, value, ok := strings.Cut(v, "=")
				if !ok {
					if strings.Contains(v, "@") {
						return in, errors.New("curl URL-encoded file input is unsupported")
					}
					value = v
					name = ""
				}
				v = strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
				if name != "" {
					v = name + "=" + v
				}
			}
			if arg == "--json" {
				jsonData = true
			} else {
				otherData = true
			}
			if jsonData && otherData {
				return in, errors.New("mixing --json with other data options is unsupported")
			}
			data = append(data, v)
		case "-F", "--form", "--form-string":
			v, e := next()
			if e != nil {
				return in, e
			}
			name, value, ok := strings.Cut(v, "=")
			if !ok || name == "" {
				return in, errors.New("curl form must use name=value")
			}
			if arg != "--form-string" && (strings.HasPrefix(value, "@") || strings.HasPrefix(value, "<") || strings.Contains(value, ";")) {
				return in, errors.New("curl file/form modifiers are unsupported; use structured multipart")
			}
			in.Multipart = append(in.Multipart, MultipartPart{Name: name, Value: value})
			form = true
		case "--max-time", "-m":
			v, e := next()
			if e != nil {
				return in, e
			}
			seconds, e := strconv.ParseFloat(v, 64)
			if e != nil || math.IsNaN(seconds) || seconds <= 0 || seconds > 120 {
				return in, errors.New("curl max-time must be 0–120 seconds (positive)")
			}
			in.TimeoutSeconds = int(math.Ceil(seconds))
		case "--max-redirs":
			v, e := next()
			if e != nil {
				return in, e
			}
			in.MaxRedirects, e = strconv.Atoi(v)
			if e != nil || in.MaxRedirects < 1 || in.MaxRedirects > 20 {
				return in, errors.New("curl max-redirs must be 1–20")
			}
		default:
			return in, errors.New("unsupported curl option; proxy/certificates/files must use caller configuration or structured request fields")
		}
	}
	if compressed && len(in.HeaderValues["Accept-Encoding"]) == 0 {
		in.HeaderValues["Accept-Encoding"] = []string{"gzip, deflate, br"}
	}
	if jsonData {
		if len(in.HeaderValues["Content-Type"]) == 0 {
			in.HeaderValues["Content-Type"] = []string{"application/json"}
		}
		if len(in.HeaderValues["Accept"]) == 0 {
			in.HeaderValues["Accept"] = []string{"application/json"}
		}
	}
	if in.URL == "" {
		return in, errors.New("curl URL is required")
	}
	if len(data) > 0 && form {
		return in, errors.New("curl data and multipart cannot be combined")
	}
	if get && form {
		return in, errors.New("curl get and multipart cannot be combined")
	}
	if len(data) > 0 {
		separator := "&"
		if jsonData {
			separator = ""
		}
		in.Body = strings.Join(data, separator)
		in.BodyEncoding = "utf8"
		if get {
			if strings.Contains(in.URL, "#") {
				return in, errors.New("curl --get URL fragments are unsupported")
			}
			sep := "?"
			if strings.Contains(in.URL, "?") {
				sep = "&"
			}
			in.URL += sep + in.Body
			in.Body = ""
			in.BodyEncoding = ""
		} else {
			in.Method = "POST"
			found := false
			for k := range in.HeaderValues {
				if strings.EqualFold(k, "Content-Type") {
					found = true
				}
			}
			if !found {
				in.HeaderValues["Content-Type"] = []string{"application/x-www-form-urlencoded"}
			}
		}
	}
	if form {
		in.Method = "POST"
	}
	if get {
		in.Method = "GET"
	}
	if explicitMethod != "" {
		in.Method = explicitMethod
	}
	if _, err = BuildRequest(in); err != nil {
		return in, err
	}
	return in, nil
}
func curlWords(command string) ([]string, error) {
	out := []string{}
	var word strings.Builder
	quote := rune(0)
	started := false
	runes := []rune(command)
	flush := func() {
		if started {
			out = append(out, word.String())
			word.Reset()
			started = false
		}
	}
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if quote == '\'' {
			if c == '\'' {
				quote = 0
			} else {
				word.WriteRune(c)
			}
			continue
		}
		if c == '$' || c == '`' {
			return nil, errors.New("shell variable/command expansion is unsupported")
		}
		if c == '\\' {
			if i+1 >= len(runes) {
				return nil, errors.New("unterminated curl escape")
			}
			next := runes[i+1]
			if quote == '"' && next != '"' && next != '\\' && next != '$' && next != '`' && next != '\n' {
				word.WriteRune(c)
				started = true
				continue
			}
			i++
			if next != '\n' {
				word.WriteRune(next)
				started = true
			}
			continue
		}
		if quote == '"' {
			if c == '"' {
				quote = 0
			} else {
				word.WriteRune(c)
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			started = true
			continue
		}
		if strings.ContainsRune(";&|<>()", c) {
			return nil, errors.New("shell operators are unsupported")
		}
		if c == 0 {
			return nil, errors.New("NUL is unsupported")
		}
		if unicode.IsSpace(c) {
			flush()
			continue
		}
		started = true
		word.WriteRune(c)
	}
	if quote != 0 {
		return nil, errors.New("unterminated curl quote")
	}
	flush()
	return out, nil
}
