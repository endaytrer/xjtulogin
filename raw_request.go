package xjtulogin

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type rawHTTPResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// isValidHeaderName reports whether name is a valid HTTP field-name token.
// We use a conservative subset of RFC7230 tchar that matches Go's net/http.
func isValidHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return false
		}
	}
	return true
}

func parseRawHTTPResponse(r *bufio.Reader) (*rawHTTPResponse, error) {
	statusLine, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	statusLine = strings.TrimRight(statusLine, "\r\n")
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("malformed HTTP status line: %q", statusLine)
	}
	codeStr := parts[1]
	statusCode := 0
	for i := 0; i < len(codeStr); i++ {
		c := codeStr[i]
		if c < '0' || c > '9' {
			return nil, fmt.Errorf("malformed HTTP status code: %q", codeStr)
		}
		statusCode = statusCode*10 + int(c-'0')
	}

	h := make(http.Header)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		name := line[:idx]
		value := strings.TrimSpace(line[idx+1:])
		if !isValidHeaderName(name) {
			// Tolerate invalid header names like `SELINUX=Server:`.
			continue
		}
		h.Add(name, value)
	}

	body, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return &rawHTTPResponse{StatusCode: statusCode, Header: h, Body: body}, nil
}

func formatCookieHeader(cookies []*http.Cookie) string {
	if len(cookies) == 0 {
		return ""
	}
	var b strings.Builder
	for i, c := range cookies {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(c.Name)
		b.WriteString("=")
		b.WriteString(c.Value)
	}
	return b.String()
}

func rawGet(u *url.URL, userAgent string, cookies []*http.Cookie) (*rawHTTPResponse, error) {
	if u == nil {
		return nil, fmt.Errorf("nil url")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(host, port)

	dialer := &net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	var err error
	if u.Scheme == "https" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: host})
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	if userAgent == "" {
		userAgent = "Go-http-client/1.1"
	}

	var req bytes.Buffer
	req.WriteString("GET ")
	req.WriteString(path)
	req.WriteString(" HTTP/1.1\r\n")
	req.WriteString("Host: ")
	req.WriteString(u.Host)
	req.WriteString("\r\n")
	req.WriteString("User-Agent: ")
	req.WriteString(userAgent)
	req.WriteString("\r\n")
	req.WriteString("Accept: */*\r\n")
	cookieHeader := formatCookieHeader(cookies)
	if cookieHeader != "" {
		req.WriteString("Cookie: ")
		req.WriteString(cookieHeader)
		req.WriteString("\r\n")
	}
	req.WriteString("Connection: close\r\n\r\n")

	if _, err := conn.Write(req.Bytes()); err != nil {
		return nil, err
	}

	return parseRawHTTPResponse(bufio.NewReader(conn))
}

// getLoginPageLenient follows redirects using raw GET to tolerate invalid header
// names on some endpoints, while still persisting cookies into the client's jar.
// It returns the final URL and an io.ReadCloser for the final response body.
func (t *XjtuLogin) getLoginPageLenient(loginURL string) (*url.URL, io.ReadCloser, error) {
	current, err := url.Parse(loginURL)
	if err != nil {
		return nil, nil, err
	}

	ua := t.headers.Get("User-Agent")
	for i := 0; i < 8; i++ {
		var cookies []*http.Cookie
		if t.client.Jar != nil {
			cookies = t.client.Jar.Cookies(current)
		}

		resp, err := rawGet(current, ua, cookies)
		if err != nil {
			return nil, nil, err
		}

		if t.client.Jar != nil {
			setCookies := (&http.Response{Header: resp.Header}).Cookies()
			if len(setCookies) > 0 {
				t.client.Jar.SetCookies(current, setCookies)
			}
		}

		if resp.StatusCode == http.StatusOK {
			return current, io.NopCloser(bytes.NewReader(resp.Body)), nil
		}

		if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusPermanentRedirect {
			loc := resp.Header.Get("Location")
			if loc == "" {
				return nil, nil, fmt.Errorf("redirect (%d) missing Location header", resp.StatusCode)
			}
			next, err := url.Parse(loc)
			if err != nil {
				return nil, nil, err
			}
			current = current.ResolveReference(next)
			continue
		}

		return nil, nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil, nil, fmt.Errorf("too many redirects")
}
