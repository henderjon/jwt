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

// Sign generates a Hmac256 hash of a string using a secret
func (s *SignHS256) Sign(json string) (string, error) {
	h := s.sign(json)
	return Base64Encode(h), nil
}

// Hash gives the name of the Signer
func (s *SignHS256) Hash() string {
	return "HS256"
}

// Verify a given JWT via the Signer
func (s *SignHS256) Verify(json, signature string) error {
	expected := s.sign(json)

	given, err := Base64Decode(signature)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected, given) {
		return errors.New("invalid signature")
	}
	return nil
}

func (s *SignHS256) sign(json string) []byte {
	h := hmac.New(crypto.SHA256.New, s.secret)
	h.Write([]byte(json))
	return h.Sum(nil)
}
