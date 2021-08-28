package password

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPasswordHashing(t *testing.T) {
	password := "my_password_1234"

	hashed, err := Hash(password)
	require.NoError(t, err)
	require.NotEmpty(t, hashed)

	valid := CheckHash(password, hashed)
	require.Equal(t, true, valid)

	valid = CheckHash("my_password", hashed)
	require.Equal(t, false, valid)
}
