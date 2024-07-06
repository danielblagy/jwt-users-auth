package auth

import (
	"context"

	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

// ErrUserNotFound is returned when user with spicified username doesn't exist.
var ErrUserNotFound = errors.New("user not found")

// ErrIncorrectPassword is returned when passwords don't match
var ErrIncorrectPassword = errors.New("password is incorrect")

func (s authService) LogIn(ctx context.Context, username, password string) (*TokenPair, error) {
	passwordHash, err := s.usersProvider.GetPasswordHash(ctx, username)
	if err != nil {
		return nil, errors.Wrap(err, "can't get user password hash")
	}
	if len(passwordHash) == 0 {
		return nil, ErrUserNotFound
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return nil, ErrIncorrectPassword
		}
		return nil, errors.Wrap(err, "can't compare passwords")
	}

	accessToken, err := s.generateJwtToken(username, AccessTokenDuration)
	if err != nil {
		return nil, errors.Wrap(err, "can't generate access token")
	}

	refreshToken, err := s.generateJwtToken(username, RefreshTokenDuration)
	if err != nil {
		return nil, errors.Wrap(err, "can't generate refresh token")
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
