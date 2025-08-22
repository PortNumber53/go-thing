package main

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestHMACSha256_FormatAndLength(t *testing.T) {
	secret := "topsecret"
	body := []byte("hello world")
	sig := hmacSha256(secret, body)
	if !strings.HasPrefix(sig, "sha256=") {
		t.Fatalf("expected prefix sha256=, got %q", sig)
	}
	hexPart := strings.TrimPrefix(sig, "sha256=")
	dec, err := hex.DecodeString(hexPart)
	if err != nil {
		t.Fatalf("expected valid hex, got error: %v", err)
	}
	if len(dec) != 32 {
		t.Fatalf("expected 32 bytes sum, got %d", len(dec))
	}
}

func TestHMACEqual_CaseInsensitive(t *testing.T) {
	secret := "s3cr3t"
	body := []byte("payload")
	want := hmacSha256(secret, body)
	upper := strings.ToUpper(want)
	lower := strings.ToLower(want)
	if !hmacEqual(upper, want) {
		t.Fatalf("expected upper to equal want in constant time")
	}
	if !hmacEqual(lower, want) {
		t.Fatalf("expected lower to equal want in constant time")
	}
}

func TestHMACEqual_NotEqual(t *testing.T) {
	secret := "a"
	body := []byte("x")
	good := hmacSha256(secret, body)
	bad := hmacSha256("b", body)
	if hmacEqual(bad, good) {
		t.Fatalf("expected signatures to differ")
	}
}
