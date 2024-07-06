package auth

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
)

// ErrNotAuthorized is returned when user doesn't have access.
var ErrNotAuthorized = errors.New("not authorized")

func (s authService) Authorize(ctx context.Context, tokens *TokenPair) (*TokenPair, string, error) {
	ok, err := s.blacklistStore.Exists(ctx, fmt.Sprintf("token-access:%s", tokens.AccessToken))
	if err != nil {
		return nil, "", errors.Wrap(err, "can't check if token is blacklisted")
	}
	if ok {
		return nil, "", ErrNotAuthorized
	}

	accessToken, refreshToken, username, err := s.verifyTokens(ctx, tokens.AccessToken, tokens.RefreshToken)
	if err != nil {
		return nil, "", err
	}

	exists, err := s.usersProvider.Exists(ctx, username)
	if err != nil {
		return nil, "", errors.Wrap(err, "can't check if user exists")
	}
	if !exists {
		return nil, "", errors.Wrap(ErrNotAuthorized, "user doesn't exist")
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, username, nil
}

// verifyTokens parses access token and tries to refresh tokens if needed.
// Returns access token & refresh token (will be same values if refresh was not needed).
func (s authService) verifyTokens(ctx context.Context, accessToken, refreshToken string) (newAccess string, newRefresh string, username string, err error) {
	newAccess = accessToken
	newRefresh = refreshToken

	username, err = s.parseJwtToken(accessToken)

	if err == nil {
		return
	}

	if !errors.Is(err, errTokenExpired) && !errors.Is(err, errInvalidToken) {
		return
	}

	newAccess, newRefresh, err = s.refreshTokens(ctx, newAccess, newRefresh)
	if err != nil {
		if errors.Is(err, errTokenExpired) {
			err = errors.Wrap(ErrNotAuthorized, "trying to refresh: token has expired")
		}
		if errors.Is(err, errInvalidToken) {
			err = errors.Wrap(ErrNotAuthorized, "trying to refresh: token is invalid")
		}
	}

	return
}
