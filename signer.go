package jwt

import (
	"crypto"
	"crypto/hmac"
	// this lib had to be linked at compile time
	_ "crypto/sha256"
	_ "crypto/sha512"
)

// SigningHash is a custom type for specifying the algorithm used
type SigningHash uint

// These specify the algorithm to be used
const (
	HS256 SigningHash = iota + 1
	HS384
	HS512
	// RS256
	// RS384
	// RS512
	// ES256
	// ES384
	// ES512
	// PS256
	// PS384
	// PS512
)

// Signer is implemented to add new methods for signing or verifying tokens.
type Signer interface {
	Verify(json, signature string) error // Returns nil if signature is valid
	Sign(signingString string) (string, error)
	Hash() string // Returns encoded signature or error
}

// SigningFunc is a signing function
type signingFunc func(json string) []byte

// NewHMACSigner is a factory for signers of the HMAC hash type
func NewHMACSigner(alg SigningHash, secret []byte) Signer {
	switch alg {
	default:
		panic("hash not implemented")
	case HS256:
		return &HMACSigner{
			name: "HS256",
			signingFunc: func(json string) []byte {
				h := hmac.New(crypto.SHA256.New, secret)
				h.Write([]byte(json))
				return h.Sum(nil)
			},
		}
	case HS384:
		return &HMACSigner{
			name: "HS384",
			signingFunc: func(json string) []byte {
				h := hmac.New(crypto.SHA384.New, secret)
				h.Write([]byte(json))
				return h.Sum(nil)
			},
		}
	case HS512:
		return &HMACSigner{
			name: "HS512",
			signingFunc: func(json string) []byte {
				h := hmac.New(crypto.SHA512.New, secret)
				h.Write([]byte(json))
				return h.Sum(nil)
			},
		}
	}
}

// NewRSASigner is a factory for signers of the RSA hash type
// func NewRSASigner(alg SigningHash, public *rsa.PublicKey, private *rsa.PrivateKey) {
// panic("hash not implemented")
// RS256
// RS384
// RS512
// PS256
// PS384
// PS512
// }

// NewECDSASigner is a factory for signers of the ECDSA hash type
// func NewECDSASigner(alg SigningHash) {
// panic("hash not implemented")
// ES256
// ES384
// ES512
// }
