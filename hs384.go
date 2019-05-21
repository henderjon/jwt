package jwt

import (
	"crypto"
	"crypto/hmac"
	"errors"
	// this lib had to be linked at compile time
	_ "crypto/sha512"
)

// SignHS384 will sign a JWT using crypto.SHA384
type SignHS384 struct {
	secret []byte
}

// NewSignHS384 is a signer
func NewSignHS384(secret []byte) *SignHS384 {
	return &SignHS384{secret}
}

// Sign generates a Hmac384 hash of a string using a secret
func (s *SignHS384) Sign(json string) (string, error) {
	h := hmac.New(crypto.SHA384.New, s.secret)
	h.Write([]byte(json))
	return Base64Encode(h.Sum(nil)), nil
}

// Hash gives the name of the Signer
func (s *SignHS384) Hash() string {
	return "HS384"
}

// Verify a given JWT via the Signer
func (s *SignHS384) Verify(json, signature string) error {
	expected, err := s.Sign(json)
	if err != nil {
		return err
	}
	if signature != expected {
		return errors.New("invalid signature")
	}
	return nil
}
