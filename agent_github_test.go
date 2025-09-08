package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"go-thing/utility"
)

func TestHMACSha256_FormatAndLength(t *testing.T) {
	secret := "topsecret"
	body := []byte("hello world")
	sig := utility.HMACSHA256(secret, body)
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
	want := utility.HMACSHA256(secret, body)
	upper := strings.ToUpper(want)
	lower := strings.ToLower(want)
	if !utility.HMACEqual(upper, want) {
		t.Fatalf("expected upper to equal want in constant time")
	}
	if !utility.HMACEqual(lower, want) {
		t.Fatalf("expected lower to equal want in constant time")
	}
}

func TestHMACEqual_NotEqual(t *testing.T) {
	secret := "a"
	body := []byte("x")
	good := utility.HMACSHA256(secret, body)
	bad := utility.HMACSHA256("b", body)
	if utility.HMACEqual(bad, good) {
		t.Fatalf("expected signatures to differ")
	}
}
