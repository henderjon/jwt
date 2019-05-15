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
func Inspect(header Header, claims Claimer) ([]byte, []byte) {
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	return h, c
}

// Serialize generates a JWT given a set of Claims
func Serialize(claims Claimer, signer Signer) string {
	h, c := Inspect(NewHeader(signer.Name()), claims)

	header := Base64Encode(h)
	payload := Base64Encode(c)

	jwt := cat(header, payload)
	return cat(jwt, signer.Sign(jwt))
}

// Unserialize decodes a JWT's claims into `dest` and verifies the JWT via the given Signer
func Unserialize(jwt string, signer Signer, dest interface{}) error {
	var err error
	tokens, err := tok(jwt)
	if err != nil {
		return err
	}

	// decode claims
	claims, err := Base64Decode(tokens[tokenClaims])
	if err != nil {
		return errors.New("invalid claims", err)
	}

	// parses claims from string to a struct
	err = json.Unmarshal([]byte(claims), dest)
	if err != nil {
		return errors.New("invalid claims", err)
	}

	v := signer.Verify(cat(tokens[tokenHeader], tokens[tokenClaims]), tokens[tokenSignature])
	if !v {
		return errors.New("invalid signature")
	}

	return nil
}
