package jwt

import (
	"crypto"
	"crypto/hmac"
	// init this hash
	_ "crypto/sha512"
)

// HMACSHA512 will sign a JWT using crypto.SHA512
type HMACSHA512 struct {
	secret []byte
}

// NewHMACSHA512 is a signer
func NewHMACSHA512(secret []byte) *HMACSHA512 {
	return &HMACSHA512{secret}
}

// Sign generates a Hmac512 hash of a string using a secret
func (s *HMACSHA512) Sign(json string) string {
	h := hmac.New(crypto.SHA512.New, s.secret)
	h.Write([]byte(json))
	return Base64Encode(h.Sum(nil))
}

// Name gives the name of the Signer
func (s *HMACSHA512) Name() string {
	return "HS512"
}

// Verify a given JWT via the Signer
func (s *HMACSHA512) Verify(json, signature string) bool {
	expected := s.Sign(json)
	if signature == expected {
		return true
	}
	return false
}
