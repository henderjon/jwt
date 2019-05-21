package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/henderjon/errors"
)

const (
	tokenHeader    = 0
	tokenClaims    = 1
	tokenSignature = 2
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

// Inspect allows the inspection of the values going into the header and payload of the JWT
func Inspect(header Header, claims Claimer) ([]byte, []byte) {
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	return h, c
}

// Serialize generates a JWT given a set of Claims
func Serialize(claims Claimer, signer Signer) (string, error) {
	h, c := Inspect(NewHeader(signer.Hash()), claims)

	header := Base64Encode(h)
	payload := Base64Encode(c)

	jwt := cat(header, payload)
	sig, err := signer.Sign(jwt)
	if err != nil {
		return "", err
	}
	return cat(jwt, sig), nil
}

// Unserialize decodes a JWT's claims into `dest` and verifies the JWT via the given Signer
func Unserialize(jwt string, signer Signer, dest interface{}) error {
	var err error
	tokens, err := tok(jwt)
	if err != nil {
		return err
	}

	err = verifyHeader(tokens[tokenHeader], signer)
	if err != nil {
		return err
	}

	err = signer.Verify(cat(tokens[tokenHeader], tokens[tokenClaims]), tokens[tokenSignature])
	if err != nil {
		return err
	}

	err = verifyClaims(tokens[tokenClaims], signer, dest)
	if err != nil {
		return err
	}
	return nil
}

func verifyHeader(header64 string, signer Signer) error {
	// decode claims
	header, err := Base64Decode(header64)
	if err != nil {
		return errors.New("invalid header", err)
	}

	h := &Header{}
	// parses claims from string to a struct
	err = json.Unmarshal([]byte(header), h)
	if err != nil {
		return errors.New("invalid header", err)
	}

	if h.Algorithm != signer.Hash() {
		return errors.Errorf("invalid algorithm: %s", h.Algorithm)
	}
	return nil
}

func verifyClaims(claims64 string, signer Signer, dest interface{}) error {
	// decode claims
	claims, err := Base64Decode(claims64)
	if err != nil {
		return errors.New("invalid claims", err)
	}

	// parses claims from string to a struct
	err = json.Unmarshal([]byte(claims), dest)
	if err != nil {
		return errors.New("invalid claims", err)
	}

	return nil
}

func tok(jwt string) ([]string, error) {
	token := strings.Split(jwt, ".")
	if len(token) != 3 {
		return []string{}, errors.New("invalid token format")
	}
	return token, nil
}

func cat(parts ...string) string {
	return strings.Join(parts, ".")
}
