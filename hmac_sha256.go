package jwt

import (
	"crypto"
	"crypto/hmac"
	"errors"
	// init this hash
	_ "crypto/sha256"
)

// ErrSignatureNotVerified means the signatures do not match
var ErrSignatureNotVerified = errors.New("signature: invalid")

// HMACSHA256 will sign a JWT using crypto.SHA256
type HMACSHA256 struct {
	secret []byte
}

// NewHMACSHA256 is a signer
func NewHMACSHA256(secret []byte) Signer {
	return &HMACSHA256{secret}
}

// Sign generates a Hmac256 hash of a string using a secret
func (s *HMACSHA256) Sign(json string) string {
	h := hmac.New(crypto.SHA256.New, s.secret)
	h.Write([]byte(json))
	return Base64Encode(h.Sum(nil))
}

// Name gives the name of the signer
func (s *HMACSHA256) Name() string {
	return "HS256"
}

// Verify a given JWT via the Signer
func (s *HMACSHA256) Verify(src, signature string) error {
	expected := s.Sign(src)
	if signature == expected {
		return nil
	}
	return ErrSignatureNotVerified
}
