package hash

import (
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

// CreatePasswordHash generated a hash from user password.
func CreatePasswordHash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", errors.Wrap(err, "can't generate password hash")
	}
	err = bcrypt.CompareHashAndPassword(hash, []byte(password))
	if err != nil {
		return "", errors.Wrap(err, "can't compare generated hash with password")
	}

	// TODO use []byte for pg column type to make hashing robust ???
	return string(hash), nil
}
