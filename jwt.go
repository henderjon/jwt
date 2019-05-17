package jwt

import (
	"time"

	"github.com/google/uuid"
)

// Header is a typical JWT header
type Header struct {
	Algorithm string `json:"alg,omitempty"` //  Algorithm
	Type      string `json:"typ,omitempty"`
}

// NewHeader returns a basic header given the algorithm
func NewHeader(alg string) Header {
	return Header{
		Algorithm: alg,
		Type:      "JWT",
	}
}

// Claimer is an interface
type Claimer interface {
	Valid() bool
}

// RegisteredClaims represents the standard registered claims of a JWT
type RegisteredClaims struct {
	Issuer    string `json:"iss,omitempty"` // (Issuer) Claim
	Subject   string `json:"sub,omitempty"` // (Subject) Claim
	Audience  string `json:"aud,omitempty"` // (Audience) Claim
	Expires   int64  `json:"exp,omitempty"` // (Expiration Time) Claim
	NotBefore int64  `json:"nbf,omitempty"` // (Not Before) Claim
	IssuedAt  int64  `json:"iat,omitempty"` // (Issued At) Claim
	ID        string `json:"jti,omitempty"` // (JWT ID) Claim
}

// NewClaims gives you a basic set of claims based on the given subject and expiration
func NewClaims(exp time.Duration) RegisteredClaims {
	return RegisteredClaims{
		Expires: time.Now().UTC().Add(exp).Unix(),
		ID:      uuid.New().String(),
	}
}

// NotActive checks to see if the claims' `nbf` field is less than the given time
func (c *RegisteredClaims) NotActive(t int64) bool {
	if c.NotBefore == 0 {
		return false
	}
	return c.NotBefore >= t
}

// IsExpired checks to see if the claims' `exp` field is less than the given time
func (c *RegisteredClaims) IsExpired(t int64) bool {
	if c.Expires == 0 {
		return false
	}
	return c.Expires <= t
}

// Valid the current claim against time.Now()
func (c *RegisteredClaims) Valid() bool {
	t := time.Now().UTC().Unix()
	return !c.NotActive(t) && !c.IsExpired(t)
}
