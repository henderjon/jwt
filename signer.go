package jwt

// Signer is implemented to add new methods for signing or verifying tokens.
type Signer interface {
	Verify(json, signature string) bool // Returns nil if signature is valid
	Sign(signingString string) string
	Name() string // Returns encoded signature or error
}
