package jwt

import (
	"crypto"
	"crypto/hmac"
	"errors"
	// this lib had to be linked at compile time
	_ "crypto/sha512"
)

// SignHS512 will sign a JWT using crypto.SHA512
type SignHS512 struct {
	secret []byte
}

// NewSignHS512 is a signer
func NewSignHS512(secret []byte) *SignHS512 {
	return &SignHS512{secret}
}

// Sign generates a Hmac512 hash of a string using a secret
func (s *SignHS512) Sign(json string) (string, error) {
	h := hmac.New(crypto.SHA512.New, s.secret)
	h.Write([]byte(json))
	return Base64Encode(h.Sum(nil)), nil
}

// Hash gives the name of the Signer
func (s *SignHS512) Hash() string {
	return "HS512"
}

// Verify a given JWT via the Signer
func (s *SignHS512) Verify(json, signature string) error {
	expected, err := s.Sign(json)
	if err != nil {
		return err
	}
	if signature != expected {
		return errors.New("invalid signature")
	}
	return nil
}
