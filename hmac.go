package jwt

import (
	"crypto/hmac"
	"errors"
	// this lib had to be linked at compile time
	_ "crypto/sha256"
)

// HMACSigner will sign a JWT using crypto.SHA256
type HMACSigner struct {
	name        string
	signingFunc signingFunc
}

// Sign generates a Hmac256 hash of a string using a secret
func (s *HMACSigner) Sign(json string) (string, error) {
	h := s.signingFunc(json)
	return Base64Encode(h), nil
}

// Hash gives the name of the Signer
func (s *HMACSigner) Hash() string {
	return s.name
}

// Verify a given JWT via the Signer
func (s *HMACSigner) Verify(json, signature string) error {
	expected := s.signingFunc(json)

	given, err := Base64Decode(signature)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected, given) {
		return errors.New("invalid signature")
	}
	return nil
}
