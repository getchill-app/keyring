package keyring_test

import (
	"os"
	"testing"

	"github.com/getchill-app/keyring"
	"github.com/getchill-app/keyring/testutil"
	"github.com/jmoiron/sqlx"
	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func testDB(t *testing.T) (*sqlx.DB, func()) {
	path := testutil.Path()
	db, err := keyring.OpenDB(path, keys.Rand32())
	require.NoError(t, err)
	closeFn := func() {
		_ = db.Close()
		_ = os.Remove(path)
	}
	return db, closeFn
}

func TestConfig(t *testing.T) {
	var err error
	path := testutil.Path()
	defer func() { _ = os.Remove(path) }()

	db, closeFn := testDB(t)
	require.NoError(t, err)
	defer closeFn()

	err = keyring.InitTables(db)
	require.NoError(t, err)

	err = keyring.SetConfig(db, "key1", "val1")
	require.NoError(t, err)
	val, err := keyring.GetConfig(db, "key1")
	require.NoError(t, err)
	require.Equal(t, "val1", val)
	err = keyring.SetConfig(db, "key1", "val1.2")
	require.NoError(t, err)
	val, err = keyring.GetConfig(db, "key1")
	require.NoError(t, err)
	require.Equal(t, "val1.2", val)
}
