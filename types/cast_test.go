package types

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestStringToInt(t *testing.T) {
	result := StringToInt("123")
	require.Equal(t, 123, result)

	result = StringToInt("-11")
	require.Equal(t, -11, result)

	result = StringToInt("XX10")
	require.Equal(t, 0, result)

	result = StringToInt(" 12 ")
	require.Equal(t, 0, result)
}
