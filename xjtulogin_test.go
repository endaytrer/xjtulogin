package xjtulogin

import (
	"os"
	"testing"
)

func TestEncryptWithPublicKey(t *testing.T) {
	pubkeyBytes, err := os.ReadFile("pubkey.pem")
	if err != nil {
		t.Fatalf("failed to read pubkey.pem: %v", err)
	}
	pubkey := string(pubkeyBytes)
	message := []byte("1234567890abcdef")
	ciphertext, err := encryptWithPublicKey(message, pubkey)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}
	if ciphertext == "" {
		t.Fatal("ciphertext is empty")
	}
	t.Logf("Encrypted: %s", ciphertext)
}
