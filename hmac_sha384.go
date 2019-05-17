package jwt

import (
	"crypto"
	"crypto/hmac"
	// init this hash
	_ "crypto/sha512"
)

// HMACSHA384 will sign a JWT using crypto.SHA384
type HMACSHA384 struct {
	secret []byte
}

// NewHMACSHA384 is a signer
func NewHMACSHA384(secret []byte) *HMACSHA384 {
	return &HMACSHA384{secret}
}

// Sign generates a Hmac384 hash of a string using a secret
func (s *HMACSHA384) Sign(json string) string {
	h := hmac.New(crypto.SHA384.New, s.secret)
	h.Write([]byte(json))
	return Base64Encode(h.Sum(nil))
}

// Name gives the name of the Signer
func (s *HMACSHA384) Name() string {
	return "HS384"
}

// Verify a given JWT via the Signer
func (s *HMACSHA384) Verify(json, signature string) bool {
	expected := s.Sign(json)
	if signature == expected {
		return true
	}
	return false
}
