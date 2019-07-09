package jwt

import (
	"time"

	"github.com/google/uuid"
)

// Header is a typical JWT header
type Header struct {
	Type      string `json:"typ,omitempty"`
	Algorithm string `json:"alg,omitempty"` //  Algorithm
}

// NewHeader returns a basic header given the algorithm
func NewHeader(alg string) Header {
	return Header{
		Type:      "JWT",
		Algorithm: alg,
	}
}

// Claimer is an interface
type Claimer interface {
	Valid() bool
}

// RegisteredClaims implements Claimer and represents the standard registered claims of a JWT
type RegisteredClaims struct {
	Audience       string `json:"aud,omitempty"` // (Audience) Claim
	Issuer         string `json:"iss,omitempty"` // (Issuer) Claim
	JWTID          string `json:"jti,omitempty"` // (JWT ID) Claim
	IssuedAt       int64  `json:"iat,omitempty"` // (Issued At) Claim
	ExpirationTime int64  `json:"exp,omitempty"` // (Expiration Time) Claim
	Subject        string `json:"sub,omitempty"` // (Subject) Claim
	NotBefore      int64  `json:"nbf,omitempty"` // (Not Before) Claim
}

// NewRegisteredClaims gives you a basic set of claims based on the given subject and expiration
func NewRegisteredClaims(exp time.Duration) RegisteredClaims {
	return RegisteredClaims{
		ExpirationTime: time.Now().UTC().Add(exp).Unix(),
		JWTID:          uuid.New().String(),
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
	if c.ExpirationTime == 0 {
		return false
	}
	return c.ExpirationTime <= t
}

// Valid implements Claimer and validates the current claim `NotActive` & `IsExpired` against time.Now()
func (c *RegisteredClaims) Valid() bool {
	t := time.Now().UTC().Unix()
	return !c.NotActive(t) && !c.IsExpired(t)
}
