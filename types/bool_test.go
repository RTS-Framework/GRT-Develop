package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBOOL_MarshalText(t *testing.T) {
	t.Run("true", func(t *testing.T) {
		output, err := TRUE.MarshalText()
		require.NoError(t, err)
		require.Equal(t, output, []byte("true"))
	})

	t.Run("false", func(t *testing.T) {
		output, err := FALSE.MarshalText()
		require.NoError(t, err)
		require.Equal(t, output, []byte("false"))
	})
}

func TestBOOL_UnmarshalText(t *testing.T) {
	t.Run("true", func(t *testing.T) {
		var b BOOL

		err := b.UnmarshalText([]byte("true"))
		require.NoError(t, err)
		require.Equal(t, TRUE, b)

		err = b.UnmarshalText([]byte("True"))
		require.NoError(t, err)
		require.Equal(t, TRUE, b)
	})

	t.Run("false", func(t *testing.T) {
		var b BOOL

		err := b.UnmarshalText([]byte("false"))
		require.NoError(t, err)
		require.Equal(t, FALSE, b)

		err = b.UnmarshalText([]byte("False"))
		require.NoError(t, err)
		require.Equal(t, FALSE, b)
	})

	t.Run("invalid", func(t *testing.T) {
		var b BOOL

		err := b.UnmarshalText([]byte("invalid"))
		require.EqualError(t, err, "invalid BOOL value")
	})
}
