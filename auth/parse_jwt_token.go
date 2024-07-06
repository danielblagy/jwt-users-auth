package auth

import (
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
)

var errInvalidToken = errors.New("token is invalid")
var errTokenExpired = errors.New("token has expired")

// parseJwtToken returns username.
func (s authService) parseJwtToken(tokenString string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &tokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.jwtSecretKey), nil
	})
	if err != nil {
		if strings.Contains(err.Error(), jwt.ErrTokenExpired.Error()) {
			return "", errTokenExpired
		}
		return "", errors.Wrap(err, "can't parse jwt token")
	}

	if claims, ok := token.Claims.(*tokenClaims); !ok || !token.Valid {
		return "", errInvalidToken
	} else {
		return claims.Username, nil
	}
}
