package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
)

var (
	AccessTokenDuration  time.Duration = time.Minute * 15
	RefreshTokenDuration time.Duration = time.Hour * 24 * 21
)

type tokenClaims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func (s authService) generateJwtToken(username string, tokenDuration time.Duration) (string, error) {
	currentTime := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, tokenClaims{
		username,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(currentTime.Add(tokenDuration)),
			IssuedAt:  jwt.NewNumericDate(currentTime),
			NotBefore: jwt.NewNumericDate(currentTime),
		},
	})

	tokenString, err := token.SignedString([]byte(s.jwtSecretKey))
	if err != nil {
		return "", errors.Wrap(err, "can't sign jwt token")
	}

	return tokenString, nil
}
