package vault

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

type vector struct {
	Name       string  `json:"name"`
	K          string  `json:"k"`
	KB64       string  `json:"kBase64url"`
	Salt       string  `json:"salt"`
	Nonce      string  `json:"nonce"`
	Passphrase *string `json:"passphrase"`
	Kind       int     `json:"kind"`
	Filename   string  `json:"filename"`
	Data       string  `json:"data"`
	Blob       string  `json:"blob"`
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile("../../../protocol/fixtures/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct{ Vectors []vector }
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	return f.Vectors
}

// The shared fixtures (generated with node:crypto) must be reproduced exactly and must decrypt.
func TestFixtures(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			pass := ""
			if v.Passphrase != nil {
				pass = *v.Passphrase
			}
			secret := Secret{Kind: Kind(v.Kind), Name: v.Filename, Data: mustHex(t, v.Data)}
			got, err := seal(secret, v.KB64, pass, mustHex(t, v.Salt), mustHex(t, v.Nonce))
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != v.Blob {
				t.Fatalf("blob mismatch\n got %x\nwant %s", got, v.Blob)
			}
			opened, err := Open(mustHex(t, v.Blob), v.KB64, pass)
			if err != nil {
				t.Fatal(err)
			}
			if opened.Kind != secret.Kind || opened.Name != secret.Name || !bytes.Equal(opened.Data, secret.Data) {
				t.Fatalf("round trip mismatch: %+v", opened)
			}
			if NeedsPassphrase(mustHex(t, v.Blob)) != (v.Passphrase != nil) {
				t.Fatal("NeedsPassphrase disagrees with fixture")
			}
		})
	}
}

func TestRoundTripRandom(t *testing.T) {
	key, err := NewKey()
	if err != nil || len(key) != 43 {
		t.Fatalf("NewKey: %q %v", key, err)
	}
	for _, pass := range []string{"", "hunter2"} {
		blob, err := Seal(Secret{Kind: File, Name: "a.txt", Data: []byte("hello")}, key, pass)
		if err != nil {
			t.Fatal(err)
		}
		s, err := Open(blob, key, pass)
		if err != nil || s.Name != "a.txt" || string(s.Data) != "hello" {
			t.Fatalf("round trip with passphrase %q: %+v %v", pass, s, err)
		}
	}
}

func TestTamperAndWrongSecrets(t *testing.T) {
	key, _ := NewKey()
	other, _ := NewKey()
	blob, _ := Seal(Secret{Data: []byte("top secret")}, key, "pw")

	if _, err := Open(blob, key, ""); !errors.Is(err, ErrPassphraseRequired) {
		t.Errorf("missing passphrase: got %v", err)
	}
	if _, err := Open(blob, key, "wrong"); !errors.Is(err, ErrDecrypt) {
		t.Errorf("wrong passphrase: got %v", err)
	}
	if _, err := Open(blob, other, "pw"); !errors.Is(err, ErrDecrypt) {
		t.Errorf("wrong key: got %v", err)
	}
	// Flipping any single byte, header included (AAD), must fail. (No passphrase: PBKDF2 is slow.)
	plain, _ := Seal(Secret{Data: []byte("top secret")}, key, "")
	for i := range plain {
		bad := bytes.Clone(plain)
		bad[i] ^= 1
		if _, err := Open(bad, key, ""); err == nil {
			t.Fatalf("flipping byte %d went unnoticed", i)
		}
	}
	if _, err := Open([]byte("short"), key, ""); !errors.Is(err, ErrNotBlob) {
		t.Errorf("short blob: got %v", err)
	}
}
