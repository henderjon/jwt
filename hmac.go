package jwt

import (
	"crypto"
	"crypto/hmac"
	"errors"
	"hash"
	// this lib had to be linked at compile time
	_ "crypto/sha256"
	_ "crypto/sha512"
)

// HMACSigner will sign a JWT using crypto.SHA256
type HMACSigner struct {
	name       string
	signerFunc signerFunc
}

// Sign generates a Hmac256 hash of a string using a secret
func (s *HMACSigner) Sign(json string) (string, error) {
	h := s.signerFunc(json)
	return Base64Encode(h), nil
}

// Hash gives the name of the Signer
func (s *HMACSigner) Hash() string {
	return s.name
}

// Verify a given JWT via the Signer
func (s *HMACSigner) Verify(json, signature string) error {
	expected := s.signerFunc(json)

	given, err := Base64Decode(signature)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected, given) {
		return errors.New("invalid signature")
	}
	return nil
}

func makeHMACSignerFunc(f func() hash.Hash, secret []byte) signerFunc {
	return func(json string) []byte {
		h := hmac.New(f, secret)
		h.Write([]byte(json))
		return h.Sum(nil)
	}
}

// NewHMACSigner is a factory for signers of the HMAC hash type
func NewHMACSigner(alg SigningHash, secret []byte) *HMACSigner {
	switch alg {
	default:
		panic("hash not implemented")
	case HS256:
		return &HMACSigner{
			name:       "HS256",
			signerFunc: makeHMACSignerFunc(crypto.SHA256.New, secret),
		}
	case HS384:
		return &HMACSigner{
			name:       "HS384",
			signerFunc: makeHMACSignerFunc(crypto.SHA384.New, secret),
		}
	case HS512:
		return &HMACSigner{
			name:       "HS512",
			signerFunc: makeHMACSignerFunc(crypto.SHA512.New, secret),
		}
	}
}
