package jwt

import (
	"errors"
	"strings"
)

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
