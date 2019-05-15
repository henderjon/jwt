package jwt

import (
	"time"

	"github.com/google/uuid"
)

// Claimer is an interface
type Claimer interface {
	Valid() bool
}

// Claims represents the standard registered claims of a JWT
type Claims struct {
	Issuer    string `json:"iss,omitempty"` // (Issuer) Claim
	Subject   string `json:"sub,omitempty"` // (Subject) Claim
	Audience  string `json:"aud,omitempty"` // (Audience) Claim
	Expires   int64  `json:"exp,omitempty"` // (Expiration Time) Claim
	NotBefore int64  `json:"nbf,omitempty"` // (Not Before) Claim
	IssuedAt  int64  `json:"iat,omitempty"` // (Issued At) Claim
	ID        string `json:"jti,omitempty"` // (JWT ID) Claim
}

// NewClaims gives you a basic set of claims based on the given subject and expiration
func NewClaims(exp time.Duration) Claims {
	return Claims{
		Expires: time.Now().UTC().Add(exp).Unix(),
		ID:      uuid.New().String(),
	}
}

// NotActive checks to see if the claims' `nbf` field is less than the given time
func (c *Claims) NotActive(t int64) bool {
	if c.NotBefore == 0 {
		return false
	}
	return c.NotBefore >= t
}

// IsExpired checks to see if the claims' `exp` field is less than the given time
func (c *Claims) IsExpired(t int64) bool {
	if c.Expires == 0 {
		return false
	}
	return c.Expires <= t
}

// Valid the current claim against time.Now()
func (c *Claims) Valid() bool {
	t := time.Now().UTC().Unix()
	return !c.NotActive(t) && !c.IsExpired(t)
}
