package auth

import "context"

//go:generate go run github.com/vektra/mockery/v2@v2.42.0 --name=AuthService --case=underscore

// AuthService defines interface for access service.
type AuthService interface {
	// Authorize parses & vaidates token, refreshes tokens if needed.
	// Returns new token pair, username and error.
	Authorize(ctx context.Context, tokens *TokenPair) (*TokenPair, string, error)
	// LogIn checks user's password and returns a generated token pair.
	LogIn(ctx context.Context, username, password string) (*TokenPair, error)
	// LogOut blacklists access and refresh tokens.
	LogOut(ctx context.Context, tokens *TokenPair) error
}

type authService struct {
	jwtSecretKey   string
	blacklistStore BlacklistStore
	usersProvider  UsersProvider
}

// NewAuthService returns an instance of access service.
func NewAuthService(
	jwtSecretKey string,
	blacklistStore BlacklistStore,
	usersProvider UsersProvider,
) AuthService {
	return &authService{
		jwtSecretKey:   jwtSecretKey,
		blacklistStore: blacklistStore,
		usersProvider:  usersProvider,
	}
}
