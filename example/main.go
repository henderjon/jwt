package main

import (
	"fmt"
	"time"

	"github.com/henderjon/jwt"
)

type token struct {
	signer jwt.Signer
}

type claims struct {
	Me string
	jwt.RegisteredClaims
}

func main() {
	expiration := time.Now().Add(time.Duration(5) * time.Hour)
	token := NewTokenizer([]byte("this is a huge secret and shouldn't be shared."))
	c := claims{
		Me: "henderjon",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpirationTime: time.Now().Add(time.Hour).UTC().Unix(),
		},
	}
	c.TTL(time.Hour)
	t, _ := token.Serialize(c)
	fmt.Println(t)

	var nc claims
	token.Unserialize(t, &nc)
	fmt.Println(nc.NotActive(expiration))
	fmt.Printf("%+v", nc)

}

func NewTokenizer(secret []byte) *token {
	return &token{
		signer: jwt.NewHMACSigner(jwt.HS256, secret),
	}
}

func (t *token) Serialize(claims interface{}) (string, error) {
	return jwt.Serialize(claims, t.signer)
}

func (t *token) Unserialize(source string, dest interface{}) error {
	return jwt.Unserialize(source, t.signer, dest)
}
