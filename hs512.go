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

// Sign generates a Hmac512 hash of a string using a secret
func (s *SignHS512) Sign(json string) (string, error) {
	h := s.sign(json)
	return Base64Encode(h), nil
}

// Hash gives the name of the Signer
func (s *SignHS512) Hash() string {
	return "HS512"
}

// Verify a given JWT via the Signer
func (s *SignHS512) Verify(json, signature string) error {
	expected := s.sign(json)

	given, err := Base64Decode(signature)
	if err != nil {
		return err
	}
	if !hmac.Equal(given, expected) {
		return errors.New("invalid signature")
	}
	return nil
}

func (s *SignHS512) sign(json string) []byte {
	h := hmac.New(crypto.SHA512.New, s.secret)
	h.Write([]byte(json))
	return h.Sum(nil)
}
