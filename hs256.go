package jwt

import (
	"crypto"
	"crypto/hmac"
	"errors"
	// this lib had to be linked at compile time
	_ "crypto/sha256"
)

// SignHS256 will sign a JWT using crypto.SHA256
type SignHS256 struct {
	secret []byte
}

// NewSignHS256 is a signer
func NewSignHS256(secret []byte) *SignHS256 {
	return &SignHS256{secret}
}

// Sign generates a Hmac256 hash of a string using a secret
func (s *SignHS256) Sign(json string) (string, error) {
	h := hmac.New(crypto.SHA256.New, s.secret)
	h.Write([]byte(json))
	return Base64Encode(h.Sum(nil)), nil
}

// Hash gives the name of the Signer
func (s *SignHS256) Hash() string {
	return "HS256"
}

// Verify a given JWT via the Signer
func (s *SignHS256) Verify(json, signature string) error {
	expected, err := s.Sign(json)
	if err != nil {
		return err
	}
	if signature != expected {
		return errors.New("invalid signature")
	}
	return nil
}
