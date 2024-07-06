package auth

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
)

func (s authService) LogOut(ctx context.Context, tokens *TokenPair) error {
	err := s.blacklistStore.Set(ctx,
		fmt.Sprintf("token-access:%s", tokens.AccessToken),
		tokens.AccessToken,
		AccessTokenDuration,
	)
	if err != nil {
		return errors.Wrap(err, "can't blacklist access token")
	}

	err = s.blacklistStore.Set(ctx,
		fmt.Sprintf("token-refresh:%s", tokens.RefreshToken),
		tokens.RefreshToken,
		RefreshTokenDuration,
	)
	if err != nil {
		return errors.Wrap(err, "can't blacklist refresh token")
	}

	return nil
}
