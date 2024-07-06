package auth

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
)

// refreshTokens parses & validates refresh token and returnes new token pair.
func (s authService) refreshTokens(ctx context.Context, accessToken, refreshToken string) (string, string, error) {
	ok, err := s.blacklistStore.Exists(ctx, fmt.Sprintf("token-refresh:%s", refreshToken))
	if err != nil {
		return "", "", errors.Wrap(err, "can't check if refresh token is blacklisted")
	}
	if ok {
		return "", "", ErrNotAuthorized
	}

	username, err := s.parseJwtToken(refreshToken)
	if err != nil {
		if errors.Is(err, errTokenExpired) {
			return "", "", errors.Wrap(ErrNotAuthorized, "refresh token has expired")
		}
		if errors.Is(err, errInvalidToken) {
			return "", "", errors.Wrap(ErrNotAuthorized, "refresh token is invalid")
		}
		return "", "", err
	}

	err = s.blacklistStore.Set(ctx, fmt.Sprintf("token-access:%s", accessToken), accessToken, AccessTokenDuration)
	if err != nil {
		return "", "", errors.Wrap(err, "can't blacklist access token")
	}

	err = s.blacklistStore.Set(ctx, fmt.Sprintf("token-refresh:%s", refreshToken), refreshToken, RefreshTokenDuration)
	if err != nil {
		return "", "", errors.Wrap(err, "can't blacklist refresh token")
	}

	newAccessToken, err := s.generateJwtToken(username, AccessTokenDuration)
	if err != nil {
		return "", "", errors.Wrap(err, "can't generate access token")
	}

	newRefreshToken, err := s.generateJwtToken(username, RefreshTokenDuration)
	if err != nil {
		return "", "", errors.Wrap(err, "can't generate refresh token")
	}

	return newAccessToken, newRefreshToken, nil
}
