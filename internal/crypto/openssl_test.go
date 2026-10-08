package crypto

import (
	"bytes"
	"os/exec"
	"testing"
)

func TestGoCryptoRoundTrip(t *testing.T) {
	passphrase := "super-secure-vault-passphrase-12345"
	original := []byte("This is a confidential secret: API_KEY=sk-live-9876543210! Multi-line\nWorks\nFlawlessly.")

	encrypted, err := Encrypt(original, passphrase)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	decrypted, err := Decrypt(encrypted, passphrase)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if !bytes.Equal(original, decrypted) {
		t.Fatalf("decrypted payload mismatch:\nExpected: %s\nGot: %s", string(original), string(decrypted))
	}
}

func TestWrongPassphrase(t *testing.T) {
	passphrase := "correct-passphrase"
	original := []byte("Super secret token")

	encrypted, err := Encrypt(original, passphrase)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	_, err = Decrypt(encrypted, "wrong-passphrase")
	if err == nil {
		t.Fatal("expected decryption error with wrong passphrase, got nil")
	}
}

func TestGenerateRandomKey(t *testing.T) {
	key1, err := GenerateRandomKey()
	if err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}
	key2, err := GenerateRandomKey()
	if err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	if len(key1) != 32 || len(key2) != 32 {
		t.Errorf("expected 32-character hex key, got %d and %d", len(key1), len(key2))
	}
	if key1 == key2 {
		t.Errorf("consecutive random keys should not be identical: %s == %s", key1, key2)
	}
}

// TestInteropWithSystemOpenSSL verifies bit-for-bit compatibility with the system's `openssl` binary.
func TestInteropWithSystemOpenSSL(t *testing.T) {
	opensslPath, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl binary not found on system, skipping CLI interop test")
	}

	passphrase := "cross-platform-test-key-999"
	secretText := "DATABASE_URL=postgres://user:secret@localhost:5432/production_db"

	// 1. Go Encrypt -> OpenSSL CLI Decrypt
	goEncrypted, err := Encrypt([]byte(secretText), passphrase)
	if err != nil {
		t.Fatalf("Go Encrypt failed: %v", err)
	}

	cmdDecrypt := exec.Command(opensslPath, "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-pass", "pass:"+passphrase)
	cmdDecrypt.Stdin = bytes.NewReader(goEncrypted)
	var opensslDecrypted bytes.Buffer
	cmdDecrypt.Stdout = &opensslDecrypted
	var errBuf bytes.Buffer
	cmdDecrypt.Stderr = &errBuf

	if err := cmdDecrypt.Run(); err != nil {
		t.Fatalf("OpenSSL CLI decryption failed: %v, stderr: %s", err, errBuf.String())
	}

	if opensslDecrypted.String() != secretText {
		t.Fatalf("OpenSSL CLI decrypted mismatch:\nExpected: %s\nGot: %s", secretText, opensslDecrypted.String())
	}

	// 2. OpenSSL CLI Encrypt -> Go Decrypt
	cmdEncrypt := exec.Command(opensslPath, "enc", "-aes-256-cbc", "-pbkdf2", "-salt", "-pass", "pass:"+passphrase)
	cmdEncrypt.Stdin = bytes.NewReader([]byte(secretText))
	var opensslEncrypted bytes.Buffer
	cmdEncrypt.Stdout = &opensslEncrypted

	if err := cmdEncrypt.Run(); err != nil {
		t.Fatalf("OpenSSL CLI encryption failed: %v", err)
	}

	goDecrypted, err := Decrypt(opensslEncrypted.Bytes(), passphrase)
	if err != nil {
		t.Fatalf("Go Decrypt of OpenSSL CLI ciphertext failed: %v", err)
	}

	if string(goDecrypted) != secretText {
		t.Fatalf("Go Decrypt mismatch:\nExpected: %s\nGot: %s", secretText, string(goDecrypted))
	}
}
