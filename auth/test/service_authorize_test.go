package test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/danielblagy/jwt-users-auth/auth"
	"github.com/danielblagy/jwt-users-auth/auth/mocks"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func Test_Authorize(t *testing.T) {
	t.Parallel()

	jwtSecretKey := "mysecretkey"
	username := "myusername"

	currentTime := time.Now()

	accessTokenStruct := jwt.NewWithClaims(jwt.SigningMethodHS256, struct {
		Username string `json:"username"`
		jwt.RegisteredClaims
	}{
		username,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(currentTime.Add(auth.AccessTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(currentTime),
			NotBefore: jwt.NewNumericDate(currentTime),
		},
	})
	accessToken, generateErr := accessTokenStruct.SignedString([]byte(jwtSecretKey))
	require.NoError(t, generateErr)

	refreshTokenStruct := jwt.NewWithClaims(jwt.SigningMethodHS256, struct {
		Username string `json:"username"`
		jwt.RegisteredClaims
	}{
		username,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(currentTime.Add(auth.AccessTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(currentTime),
			NotBefore: jwt.NewNumericDate(currentTime),
		},
	})
	refreshToken, generateErr := refreshTokenStruct.SignedString([]byte(jwtSecretKey))
	require.NoError(t, generateErr)

	tokens := &auth.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	t.Run("error: can't check if token is blacklisted", func(t *testing.T) {
		t.Parallel()

		expectedErr := errors.New("some error")

		blacklistStore := new(mocks.BlacklistStore)
		blacklistStore.
			On("Exists", mock.AnythingOfType("context.backgroundCtx"), fmt.Sprintf("token-access:%s", tokens.AccessToken)).
			Return(false, expectedErr)

		service := auth.NewAuthService(jwtSecretKey, blacklistStore, nil)
		resultTokens, resultUsername, err := service.Authorize(context.Background(), tokens)
		require.ErrorIs(t, err, expectedErr)
		require.ErrorContains(t, err, "can't check if token is blacklisted")
		require.Nil(t, resultTokens)
		require.Empty(t, resultUsername)
	})

	t.Run("error: not authorized, access token is blacklisted", func(t *testing.T) {
		t.Parallel()

		expectedErr := auth.ErrNotAuthorized

		blacklistStore := new(mocks.BlacklistStore)
		blacklistStore.
			On("Exists", mock.AnythingOfType("context.backgroundCtx"), fmt.Sprintf("token-access:%s", tokens.AccessToken)).
			Return(true, nil)

		service := auth.NewAuthService(jwtSecretKey, blacklistStore, nil)
		resultTokens, resultUsername, err := service.Authorize(context.Background(), tokens)
		require.ErrorIs(t, err, expectedErr)
		require.Nil(t, resultTokens)
		require.Empty(t, resultUsername)
	})

	t.Run("error: can't check if user exists", func(t *testing.T) {
		t.Parallel()

		expectedErr := errors.New("some error")

		blacklistStore := new(mocks.BlacklistStore)
		blacklistStore.
			On("Exists", mock.AnythingOfType("context.backgroundCtx"), fmt.Sprintf("token-access:%s", tokens.AccessToken)).
			Return(false, nil)

		usersProvider := new(mocks.UsersProvider)
		usersProvider.
			On("Exists", mock.AnythingOfType("context.backgroundCtx"), username).
			Return(false, expectedErr)

		service := auth.NewAuthService(jwtSecretKey, blacklistStore, usersProvider)
		resultTokens, resultUsername, err := service.Authorize(context.Background(), tokens)
		require.ErrorIs(t, err, expectedErr)
		require.ErrorContains(t, err, "can't check if user exists")
		require.Nil(t, resultTokens)
		require.Empty(t, resultUsername)
	})

	t.Run("error: not authorized, user doesn't exist", func(t *testing.T) {
		t.Parallel()

		expectedErr := auth.ErrNotAuthorized

		blacklistStore := new(mocks.BlacklistStore)
		blacklistStore.
			On("Exists", mock.AnythingOfType("context.backgroundCtx"), fmt.Sprintf("token-access:%s", tokens.AccessToken)).
			Return(false, nil)

		usersProvider := new(mocks.UsersProvider)
		usersProvider.
			On("Exists", mock.AnythingOfType("context.backgroundCtx"), username).
			Return(false, nil)

		service := auth.NewAuthService(jwtSecretKey, blacklistStore, usersProvider)
		resultTokens, resultUsername, err := service.Authorize(context.Background(), tokens)
		require.ErrorIs(t, err, expectedErr)
		require.ErrorContains(t, err, "user doesn't exist")
		require.Nil(t, resultTokens)
		require.Empty(t, resultUsername)
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		blacklistStore := new(mocks.BlacklistStore)
		blacklistStore.
			On("Exists", mock.AnythingOfType("context.backgroundCtx"), fmt.Sprintf("token-access:%s", tokens.AccessToken)).
			Return(false, nil)

		usersProvider := new(mocks.UsersProvider)
		usersProvider.
			On("Exists", mock.AnythingOfType("context.backgroundCtx"), username).
			Return(true, nil)

		service := auth.NewAuthService(jwtSecretKey, blacklistStore, usersProvider)
		resultTokens, resultUsername, err := service.Authorize(context.Background(), tokens)
		require.NoError(t, err)
		require.NotNil(t, resultTokens)
		require.Equal(t, accessToken, resultTokens.AccessToken)
		require.Equal(t, refreshToken, resultTokens.RefreshToken)
		require.Equal(t, username, resultUsername)
	})
}
