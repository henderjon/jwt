package jwt

import (
	"encoding/base64"
	"strings"
)

// removing/adding the '=' is to make the JWT URL friendly?

// Base64Encode takes a []byte and returns a base 64 encoded string
func Base64Encode(src []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(src), "=")
}

// Base64Decode takes in a base 64 encoded string and returns the
// decoded []byte
func Base64Decode(src string) ([]byte, error) {
	if l := len(src) % 4; l > 0 {
		src += strings.Repeat("=", 4-l)
	}
	decoded, err := base64.URLEncoding.DecodeString(src)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}
