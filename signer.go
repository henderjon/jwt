package jwt

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

// signerFunc is a signing function
type signerFunc func(json string) []byte
