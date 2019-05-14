package jwt

import (
	"encoding/json"

	"github.com/henderjon/errors"
)

const (
	tokenHeader    = 0
	tokenClaims    = 1
	tokenSignature = 2
)

// Inspect allows the inspection of the values going into the header and payload of the JWT
func Inspect(claims Claimer, signer Signer) ([]byte, []byte) {
	h, _ := json.Marshal(NewHeader(signer.Name()))
	c, _ := json.Marshal(claims)
	return h, c
}

// Serialize generates a jwt.
func Serialize(claims Claimer, signer Signer) string {
	h, c := Inspect(claims, signer)

	header := Base64Encode(h)
	payload := Base64Encode(c)

	jwt := cat(header, payload)
	return cat(jwt, signer.Sign(jwt))
}

// Unserialize decodes a thing
func Unserialize(dest interface{}, jwt string, signer Signer) error {
	var err error
	tokens, err := tok(jwt)
	if err != nil {
		return err
	}
	// decode claims
	claims, err := Base64Decode(tokens[tokenClaims])
	if err != nil {
		return errors.New("Invalid claims", err)
	}
	// parses claims from string to a struct
	err = json.Unmarshal([]byte(claims), dest)
	if err != nil {
		return errors.New("Invalid claims", err)
	}
	return signer.Verify(cat(tokens[tokenHeader], tokens[tokenClaims]), tokens[tokenSignature])
}
