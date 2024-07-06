package auth

import (
	"context"
	"time"
)

//go:generate go run github.com/vektra/mockery/v2@v2.42.0 --name=BlacklistStore --case=underscore

// BlacklistStore defines an interface for quick-access persistent key-value storage for jwt token blacklist.
// It stores tokens that can no longer be used due to user logging out of the system.
type BlacklistStore interface {
	// Get returns true if key exists in persistent store.
	Exists(ctx context.Context, key string) (bool, error)
	// Set set's a key-value pair.
	Set(ctx context.Context, key, value string, expiration time.Duration) error
}
