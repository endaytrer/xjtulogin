package xjtulogin

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// parseRedirectLocationFromReader parses an HTTP/1.x response stream just enough
// to obtain the status code and Location header.
//
// It is intentionally tolerant of invalid header field names (e.g. `SELINUX=Server:`),
// since some servers incorrectly emit them and Go's net/http refuses to parse such
// responses.
func parseRedirectLocationFromReader(r *bufio.Reader) (statusCode int, location string, err error) {
	statusLine, err := r.ReadString('\n')
	if err != nil {
		return 0, "", err
	}
	statusLine = strings.TrimRight(statusLine, "\r\n")
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		return 0, "", fmt.Errorf("malformed HTTP status line: %q", statusLine)
	}

	statusCode = 0
	for i := 0; i < len(parts[1]); i++ {
		c := parts[1][i]
		if c < '0' || c > '9' {
			return 0, "", fmt.Errorf("malformed HTTP status code: %q", parts[1])
		}
		statusCode = statusCode*10 + int(c-'0')
	}

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return statusCode, "", err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}

		// Minimal permissive parsing: only extract Location.
		// (We don't attempt to validate header field-name syntax.)
		if strings.HasPrefix(strings.ToLower(line), "location:") {
			location = strings.TrimSpace(line[len("location:"):])
		}
	}

	return statusCode, location, nil
}

// GetRedirectLocationRaw performs a minimal raw HTTP/HTTPS GET request (HTTP/1.1)
// and returns the resolved Location URL from the response.
//
// This is useful when the peer sends invalid header field names that make Go's
// net/http client fail with errors like:
//
//	"net/http: HTTP/1.x transport connection broken: malformed MIME header line: SELINUX=Server:"
func GetRedirectLocationRaw(rawURL string, userAgent string) (locationURL string, statusCode int, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", 0, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", 0, fmt.Errorf("unsupported scheme: %s", u.Scheme)
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

	var conn net.Conn
	if u.Scheme == "https" {
		conn, err = tls.Dial("tcp", addr, &tls.Config{ServerName: host})
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		return "", 0, err
	}
	defer conn.Close()

	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	if userAgent == "" {
		userAgent = "Go-http-client/1.1"
	}

	// Connection: close keeps parsing simple.
	_, err = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: close\r\n\r\n", path, u.Host, userAgent)
	if err != nil {
		return "", 0, err
	}

	statusCode, location, err := parseRedirectLocationFromReader(bufio.NewReader(conn))
	if err != nil {
		return "", statusCode, err
	}
	if location == "" {
		return "", statusCode, fmt.Errorf("missing Location header")
	}

	loc, err := url.Parse(location)
	if err != nil {
		return "", statusCode, err
	}
	loc = u.ResolveReference(loc)
	return loc.String(), statusCode, nil
}
