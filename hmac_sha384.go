package jwt

import (
	"crypto"
	"crypto/hmac"
	"errors"
	// this lib had to be linked at compile time
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
func (s *HMACSHA384) Sign(json string) (string, error) {
	h := hmac.New(crypto.SHA384.New, s.secret)
	h.Write([]byte(json))
	return Base64Encode(h.Sum(nil)), nil
}

// Hash gives the name of the Signer
func (s *HMACSHA384) Hash() string {
	return "HS384"
}

// Verify a given JWT via the Signer
func (s *HMACSHA384) Verify(json, signature string) error {
	expected, err := s.Sign(json)
	if err != nil {
		return err
	}
	if signature != expected {
		return errors.New("invalid signature")
	}
	return nil
}
