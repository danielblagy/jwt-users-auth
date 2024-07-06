package test

import (
	"context"
	"errors"
	"testing"

	"github.com/danielblagy/jwt-users-auth/auth"
	"github.com/danielblagy/jwt-users-auth/auth/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func Test_LogIn(t *testing.T) {
	t.Parallel()

	jwtSecretKey := "mysecretkey"
	username := "myusername"
	password := "mypassword"

	passwordHashBytes, hashErr := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, hashErr)
	passwordHash := string(passwordHashBytes)

	t.Run("error: can't get user password hash", func(t *testing.T) {
		t.Parallel()

		expectedErr := errors.New("some error")

		usersProvider := new(mocks.UsersProvider)
		usersProvider.
			On("GetPasswordHash", mock.AnythingOfType("context.backgroundCtx"), username).
			Return("", expectedErr)

		service := auth.NewAuthService(jwtSecretKey, nil, usersProvider)
		tokens, err := service.LogIn(context.Background(), username, password)
		require.ErrorIs(t, err, expectedErr)
		require.ErrorContains(t, err, "can't get user password hash")
		require.Nil(t, tokens)
	})

	t.Run("error: user not found", func(t *testing.T) {
		t.Parallel()

		expectedErr := auth.ErrUserNotFound

		usersProvider := new(mocks.UsersProvider)
		usersProvider.
			On("GetPasswordHash", mock.AnythingOfType("context.backgroundCtx"), username).
			Return("", nil)

		service := auth.NewAuthService(jwtSecretKey, nil, usersProvider)
		tokens, err := service.LogIn(context.Background(), username, password)
		require.ErrorIs(t, err, expectedErr)
		require.Nil(t, tokens)
	})

	t.Run("error: incorrect password", func(t *testing.T) {
		t.Parallel()

		expectedErr := auth.ErrIncorrectPassword

		usersProvider := new(mocks.UsersProvider)
		usersProvider.
			On("GetPasswordHash", mock.AnythingOfType("context.backgroundCtx"), username).
			Return(passwordHash, nil)

		service := auth.NewAuthService(jwtSecretKey, nil, usersProvider)
		tokens, err := service.LogIn(context.Background(), username, "mypassword123")
		require.ErrorIs(t, err, expectedErr)
		require.Nil(t, tokens)
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		usersProvider := new(mocks.UsersProvider)
		usersProvider.
			On("GetPasswordHash", mock.AnythingOfType("context.backgroundCtx"), username).
			Return(passwordHash, nil)

		service := auth.NewAuthService(jwtSecretKey, nil, usersProvider)
		tokens, err := service.LogIn(context.Background(), username, password)
		require.NoError(t, err)
		require.NotNil(t, tokens)
		require.NotEmpty(t, tokens.AccessToken)
		require.NotEmpty(t, tokens.RefreshToken)
	})
}
