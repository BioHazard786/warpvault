// Package vault implements the Warpvault blob format (protocol/PROTOCOL.md): AES-256-GCM with a key
// derived from the link key and an optional passphrase. The server only ever sees the blob.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	version       = 0x01
	flagPass      = 0x01
	saltLen       = 16
	nonceLen      = 12
	headerLen     = 2 + saltLen + nonceLen // also the GCM additional data
	tagLen        = 16
	keyLen        = 32
	pbkdf2Iter    = 600_000
	infoPlain     = "warpvault/1"
	infoPass      = "warpvault/1/pass"
	maxNameLen    = 1<<16 - 1
	plainOverhead = 1 + 2 // kind + nameLen
)

// Kind says what a secret contains.
type Kind byte

const (
	Text Kind = 0
	File Kind = 1
)

var (
	ErrNotBlob            = errors.New("not a warpvault blob (wrong version or too short)")
	ErrPassphraseRequired = errors.New("this secret needs a passphrase")
	ErrDecrypt            = errors.New("decryption failed: wrong key or passphrase, or the data was modified")
)

// Secret is the plaintext inside a blob.
type Secret struct {
	Kind Kind
	Name string // file name (Kind == File), else empty
	Data []byte
}

// NewKey returns a fresh link key: 32 random bytes, base64url without padding.
func NewKey() (string, error) {
	k := make([]byte, keyLen)
	if _, err := rand.Read(k); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(k), nil
}

// NeedsPassphrase reports whether the blob header says a passphrase is required.
func NeedsPassphrase(blob []byte) bool {
	return len(blob) >= headerLen+tagLen && blob[0] == version && blob[1]&flagPass != 0
}

// Seal encrypts s under the link key (and passphrase, if not empty) with a fresh salt and nonce.
func Seal(s Secret, key, passphrase string) ([]byte, error) {
	salt := make([]byte, saltLen)
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return seal(s, key, passphrase, salt, nonce)
}

func seal(s Secret, key, passphrase string, salt, nonce []byte) ([]byte, error) {
	if len(s.Name) > maxNameLen {
		return nil, errors.New("file name too long")
	}
	plain := make([]byte, 0, plainOverhead+len(s.Name)+len(s.Data))
	plain = append(plain, byte(s.Kind))
	plain = binary.BigEndian.AppendUint16(plain, uint16(len(s.Name)))
	plain = append(plain, s.Name...)
	plain = append(plain, s.Data...)

	aead, err := newAEAD(key, passphrase, salt)
	if err != nil {
		return nil, err
	}
	var flags byte
	if passphrase != "" {
		flags = flagPass
	}
	out := make([]byte, 0, headerLen+len(plain)+tagLen)
	out = append(out, version, flags)
	out = append(out, salt...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plain, out[:headerLen]), nil
}

// Open decrypts a blob. An empty passphrase on a passphrase-protected blob returns ErrPassphraseRequired.
func Open(blob []byte, key, passphrase string) (Secret, error) {
	if len(blob) < headerLen+tagLen || blob[0] != version || blob[1]&^flagPass != 0 {
		return Secret{}, ErrNotBlob
	}
	if NeedsPassphrase(blob) && passphrase == "" {
		return Secret{}, ErrPassphraseRequired
	}
	if !NeedsPassphrase(blob) {
		passphrase = "" // ignore a passphrase the sender never set
	}
	salt := blob[2 : 2+saltLen]
	nonce := blob[2+saltLen : headerLen]
	aead, err := newAEAD(key, passphrase, salt)
	if err != nil {
		return Secret{}, err
	}
	plain, err := aead.Open(nil, nonce, blob[headerLen:], blob[:headerLen])
	if err != nil {
		return Secret{}, ErrDecrypt
	}
	if len(plain) < plainOverhead {
		return Secret{}, ErrNotBlob
	}
	nameLen := int(binary.BigEndian.Uint16(plain[1:3]))
	if len(plain) < plainOverhead+nameLen {
		return Secret{}, ErrNotBlob
	}
	return Secret{
		Kind: Kind(plain[0]),
		Name: string(plain[3 : 3+nameLen]),
		Data: plain[3+nameLen:],
	}, nil
}

// newAEAD derives the AES-256-GCM key: HKDF(k) or HKDF(k || PBKDF2(passphrase)).
func newAEAD(key, passphrase string, salt []byte) (cipher.AEAD, error) {
	k, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil || len(k) != keyLen {
		return nil, fmt.Errorf("invalid key in link (expected 43 base64url characters)")
	}
	ikm, info := k, infoPlain
	if passphrase != "" {
		pk, err := pbkdf2.Key(sha256.New, passphrase, salt, pbkdf2Iter, keyLen)
		if err != nil {
			return nil, err
		}
		ikm, info = append(append([]byte{}, k...), pk...), infoPass
	}
	dk, err := hkdf.Key(sha256.New, ikm, salt, info, keyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
