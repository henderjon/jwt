package jwt

// Header is a header
type Header struct {
	Algorithm string `json:"alg"` //  Algorithm
	Type      string `json:"typ"`
}

// NewHeader is a constructor
func NewHeader(alg string) Header {
	return Header{
		Algorithm: alg,
		Type:      "JWT",
	}
}
