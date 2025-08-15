package xjtulogin

import (
	"os"
	"testing"
)

func TestLogin(t *testing.T) {
	username, success := os.LookupEnv("XJTU_USERNAME")
	if !success {
		t.Fatal("XJTU_USERNAME not set")
	}
	password, success := os.LookupEnv("XJTU_PASSWORD")
	if !success {
		t.Fatal("XJTU_PASSWORD not set")
	}
	redir_url, err := Login("http://gmis.xjtu.edu.cn/pyxx/sso/login", username, password)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	t.Logf("Redirect URL: %s", redir_url)
}
