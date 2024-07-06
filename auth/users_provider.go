package auth

import "context"

//go:generate go run github.com/vektra/mockery/v2@v2.42.0 --name=UsersProvider --case=underscore

// UsersProvider defines an interface to access users storage.
type UsersProvider interface {
	// GetPasswordHash returns password hash of a user by unique username.
	// Must return an empty string and nil error if user was not found.
	GetPasswordHash(ctx context.Context, username string) (string, error)
	// Exists returns true if a user with username exists.
	Exists(ctx context.Context, username string) (bool, error)
}
