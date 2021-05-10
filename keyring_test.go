package keyring_test

import (
	"testing"

	"github.com/getchill-app/keyring"
	"github.com/getchill-app/keyring/testutil"
	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestSetup(t *testing.T) {
	var err error
	kr, closeFn := testutil.NewTestKeyring(t)
	defer closeFn()

	mk := keys.Rand32()

	err = kr.Unlock(mk)
	require.EqualError(t, err, "setup needed")
	require.Equal(t, keyring.SetupNeeded, kr.Status())

	err = kr.Setup(mk)
	require.NoError(t, err)
	require.Equal(t, keyring.Unlocked, kr.Status())
	err = kr.Lock()
	require.NoError(t, err)

	err = kr.Setup(mk)
	require.EqualError(t, err, "already setup")

	// Unlock multiple times
	err = kr.Unlock(mk)
	require.NoError(t, err)
	require.Equal(t, keyring.Unlocked, kr.Status())
	err = kr.Unlock(mk)
	require.NoError(t, err)

	// Lock, unlock
	err = kr.Lock()
	require.NoError(t, err)
	require.Equal(t, keyring.Locked, kr.Status())
	err = kr.Unlock(mk)
	require.NoError(t, err)
}

func TestLocked(t *testing.T) {
	var err error
	kr, closeFn := testutil.NewTestKeyring(t)
	defer closeFn()

	mk := keys.Rand32()

	err = kr.Setup(mk)
	require.NoError(t, err)

	// Try accessing keyring while locked
	err = kr.Lock()
	require.NoError(t, err)
	_, err = kr.Key(keys.RandID("test"))
	require.EqualError(t, err, "keyring is locked")
	_, err = kr.Keys()
	require.EqualError(t, err, "keyring is locked")
}

func TestInvalidPassword(t *testing.T) {
	var err error
	kr, closeFn := testutil.NewTestKeyring(t)
	defer closeFn()

	_, err = kr.SetupPassword("testpassword")
	require.NoError(t, err)
	require.Equal(t, keyring.Unlocked, kr.Status())

	_, err = kr.UnlockWithPassword("invalidpassword")
	require.EqualError(t, err, "invalid auth")
}
