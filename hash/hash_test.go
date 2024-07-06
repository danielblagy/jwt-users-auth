package hash

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func Test_CreatePasswordHash(t *testing.T) {
	t.Parallel()

	password := "mypassword123"

	result, err := CreatePasswordHash(password)
	require.NoError(t, err)
	compareErr := bcrypt.CompareHashAndPassword([]byte(result), []byte(password))
	require.NoError(t, compareErr)
}
