package jwt

// signingHash is a custom type for specifying the algorithm used
type signingHash uint

// These specify the algorithm to be used
const (
	HS256 signingHash = iota + 1
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
	// Verify checks to see that the signed strings match; returns nil if signature is valid
	Verify(control, variable string) error
	// Sign generates a hash of a string using the previously provided algorithm
	Sign(signingString string) (string, error)
	// Name returns the name of the algorithm being used
	Name() string
}

// SignerFunc is a signing function, READ: it does the work
type SignerFunc func(json string) []byte
