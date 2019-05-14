package jwt

// Signer implemented to add new methods for signing or verifying tokens.
type Signer interface {
	Verify(signingString, signature string) error // Returns nil if signature is valid
	Sign(signingString string) string
	Name() string // Returns encoded signature or error
}
