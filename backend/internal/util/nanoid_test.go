package util

import (
	"strings"
	"testing"
)

func TestGenerateID(t *testing.T) {
	id, err := GenerateID(10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(id) != 10 {
		t.Errorf("expected length 10, got %d", len(id))
	}

	for _, c := range id {
		if !strings.ContainsRune(DefaultAlphabet, c) {
			t.Errorf("character %q not in alphabet", c)
		}
	}
}

func TestGenerateDeleteToken(t *testing.T) {
	token, err := GenerateDeleteToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(token) != 64 { // 32 bytes in hex = 64 characters
		t.Errorf("expected token length 64, got %d", len(token))
	}
}
