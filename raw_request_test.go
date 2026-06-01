package xjtulogin

import (
	"bufio"
	"strings"
	"testing"
)

func TestIsValidHeaderName(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		{"Server", true},
		{"Content-Type", true},
		{"X-Test-123", true},
		{"SELINUX=Server", false},
		{"Bad Space", false},
		{"", false},
	}

	for _, tc := range cases {
		if got := isValidHeaderName(tc.name); got != tc.ok {
			t.Fatalf("isValidHeaderName(%q)=%v, want %v", tc.name, got, tc.ok)
		}
	}
}

func TestParseRawHTTPResponse_IgnoresInvalidHeaderNameButKeepsLocation(t *testing.T) {
	raw := "HTTP/1.1 301 Moved Permanently\r\n" +
		"SELINUX=Server:  \r\n" +
		"Date: Mon, 01 Jun 2026 00:00:00 GMT\r\n" +
		"Location: https://gmis.xjtu.edu.cn/pyxx/sso/login\r\n" +
		"\r\n"

	resp, err := parseRawHTTPResponse(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 301 {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "https://gmis.xjtu.edu.cn/pyxx/sso/login" {
		t.Fatalf("unexpected location: %q", got)
	}
	// Invalid header name should be ignored and thus not present.
	if got := resp.Header.Get("SELINUX=Server"); got != "" {
		t.Fatalf("unexpected invalid header present: %q", got)
	}
}
