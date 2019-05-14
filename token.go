package jwt

import (
	"errors"
	"strings"
)

// ErrInvalidTokenStructure are errors for users
var ErrInvalidTokenStructure = errors.New("invalid token format")

func tok(jwt string) ([]string, error) {
	token := strings.Split(jwt, ".")
	if len(token) != 3 {
		return []string{}, ErrInvalidTokenStructure
	}
	return token, nil
}

func cat(parts ...string) string {
	return strings.Join(parts, ".")
}
