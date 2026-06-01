package xjtulogin

import (
	"bufio"
	"strings"
	"testing"
)

func TestParseRedirectLocationFromReader_AllowsInvalidHeaderName(t *testing.T) {
	raw := "HTTP/1.1 301 Moved Permanently\r\n" +
		"SELINUX=Server:  \r\n" +
		"Date: Mon, 01 Jun 2026 00:00:00 GMT\r\n" +
		"Location: https://gmis.xjtu.edu.cn/pyxx/sso/login\r\n" +
		"\r\n"

	status, loc, err := parseRedirectLocationFromReader(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != 301 {
		t.Fatalf("unexpected status: %d", status)
	}
	if loc != "https://gmis.xjtu.edu.cn/pyxx/sso/login" {
		t.Fatalf("unexpected location: %q", loc)
	}
}

func TestParseRedirectLocationFromReader_NoLocation(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"

	status, loc, err := parseRedirectLocationFromReader(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != 200 {
		t.Fatalf("unexpected status: %d", status)
	}
	if loc != "" {
		t.Fatalf("expected empty location, got: %q", loc)
	}
}
