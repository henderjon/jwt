package jwt

// Signer is implemented to add new methods for signing or verifying tokens.
type Signer interface {
	Verify(json, signature string) error // Returns nil if signature is valid
	Sign(signingString string) (string, error)
	Hash() string // Returns encoded signature or error
}
