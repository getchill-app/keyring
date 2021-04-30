package testutil

import (
	"os"
	"testing"

	"github.com/getchill-app/keyring"
	"github.com/getchill-app/keyring/auth"
	"github.com/stretchr/testify/require"
)

func NewTestKeyring(t *testing.T) (*keyring.Keyring, func()) {
	var err error
	path := Path()
	authPath := Path()

	auth, err := auth.NewDB(authPath)
	require.NoError(t, err)

	vlt, err := keyring.New(path, auth)
	require.NoError(t, err)

	closeFn := func() {
		err = auth.Close()
		require.NoError(t, err)
		err = os.Remove(authPath)
		require.NoError(t, err)
		err = vlt.Lock()
		require.NoError(t, err)
		err = os.Remove(path)
		require.NoError(t, err)
	}

	return vlt, closeFn
}

func NewTestKeyringWithSetup(t *testing.T, password string) (*keyring.Keyring, func()) {
	kr, closeFn := NewTestKeyring(t)
	_, err := kr.SetupPassword(password)
	require.NoError(t, err)
	return kr, closeFn
}
