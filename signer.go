package jwt

import "crypto/rsa"

// SigningHash is a custom type for specifying the algorithm used
type SigningHash uint

// These specify the algorithm to be used
const (
	HS256 SigningHash = iota + 1
	HS384
	HS512
	RS256
	RS384
	RS512
	ES256
	ES384
	ES512
	PS256
	PS384
	PS512
)

// Signer is implemented to add new methods for signing or verifying tokens.
type Signer interface {
	Verify(json, signature string) error // Returns nil if signature is valid
	Sign(signingString string) (string, error)
	Hash() string // Returns encoded signature or error
}

// NewHMACSigner is a factory for signers of the HMAC hash type
func NewHMACSigner(alg SigningHash, secret []byte) Signer {
	switch alg {
	default:
		panic("hash not implemented")
	case HS256:
		return &SignHS256{secret}
	case HS384:
		return &SignHS384{secret}
	case HS512:
		return &SignHS512{secret}
	}
}

// NewRSASigner is a factory for signers of the RSA hash type
func NewRSASigner(alg SigningHash, public *rsa.PublicKey, private *rsa.PrivateKey) {
	panic("hash not implemented")
	// RS256
	// RS384
	// RS512
	// PS256
	// PS384
	// PS512
}

// NewECDSASigner is a factory for signers of the ECDSA hash type
func NewECDSASigner(alg SigningHash) {
	panic("hash not implemented")
	// ES256
	// ES384
	// ES512
}
