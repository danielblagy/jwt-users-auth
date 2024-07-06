package test

import (
	"context"
	"errors"
	"testing"

	"github.com/danielblagy/jwt-users-auth/auth"
	"github.com/danielblagy/jwt-users-auth/auth/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func Test_LogOut(t *testing.T) {
	t.Parallel()

	jwtSecretKey := "mysecretkey"
	tokens := &auth.TokenPair{
		AccessToken:  "myaccesstoken",
		RefreshToken: "myrefreshtoken",
	}
	accessTokenBlacklistKey := "token-access:myaccesstoken"
	refreshTokenBlacklistKey := "token-refresh:myrefreshtoken"

	t.Run("error: can't blacklist access token", func(t *testing.T) {
		t.Parallel()

		expectedErr := errors.New("some error")

		blacklistStore := new(mocks.BlacklistStore)
		blacklistStore.
			On("Set", mock.AnythingOfType("context.backgroundCtx"), accessTokenBlacklistKey, tokens.AccessToken, auth.AccessTokenDuration).
			Return(expectedErr)

		service := auth.NewAuthService(jwtSecretKey, blacklistStore, nil)
		err := service.LogOut(context.Background(), tokens)
		require.ErrorIs(t, err, expectedErr)
		require.ErrorContains(t, err, "can't blacklist access token")
	})

	t.Run("error: can't blacklist refresh token", func(t *testing.T) {
		t.Parallel()

		expectedErr := errors.New("some error")

		blacklistStore := new(mocks.BlacklistStore)
		blacklistStore.
			On("Set", mock.AnythingOfType("context.backgroundCtx"), accessTokenBlacklistKey, tokens.AccessToken, auth.AccessTokenDuration).
			Return(nil)
		blacklistStore.
			On("Set", mock.AnythingOfType("context.backgroundCtx"), refreshTokenBlacklistKey, tokens.RefreshToken, auth.RefreshTokenDuration).
			Return(expectedErr)

		service := auth.NewAuthService(jwtSecretKey, blacklistStore, nil)
		err := service.LogOut(context.Background(), tokens)
		require.ErrorIs(t, err, expectedErr)
		require.ErrorContains(t, err, "can't blacklist refresh token")
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		blacklistStore := new(mocks.BlacklistStore)
		blacklistStore.
			On("Set", mock.AnythingOfType("context.backgroundCtx"), accessTokenBlacklistKey, tokens.AccessToken, auth.AccessTokenDuration).
			Return(nil)
		blacklistStore.
			On("Set", mock.AnythingOfType("context.backgroundCtx"), refreshTokenBlacklistKey, tokens.RefreshToken, auth.RefreshTokenDuration).
			Return(nil)

		service := auth.NewAuthService(jwtSecretKey, blacklistStore, nil)
		err := service.LogOut(context.Background(), tokens)
		require.NoError(t, err)
	})
}
