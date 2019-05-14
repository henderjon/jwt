package jwt

// Header is a typical JWT header
type Header struct {
	Algorithm string `json:"alg"` //  Algorithm
	Type      string `json:"typ"`
}

// NewHeader returns a basic header given the algorithm
func NewHeader(alg string) Header {
	return Header{
		Algorithm: alg,
		Type:      "JWT",
	}
}
