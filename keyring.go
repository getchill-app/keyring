package keyring

import (
	"database/sql"
	"os"

	"github.com/getchill-app/keyring/auth"
	"github.com/jmoiron/sqlx"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys-ext/auth/fido2"
	"github.com/keys-pub/keys/api"

	"github.com/pkg/errors"
)

// ErrLocked if locked.
var ErrLocked = errors.New("vault is locked")

// ErrInvalidAuth if auth is invalid.
var ErrInvalidAuth = auth.ErrInvalidAuth

// ErrSetupNeeded if setup if needed.
var ErrSetupNeeded = errors.New("setup needed")

// Keyring stores secrets.
type Keyring struct {
	path string
	db   *sqlx.DB

	auth *auth.DB

	fido2Plugin fido2.FIDO2Server
}

// New vault.
func New(path string, auth *auth.DB) (*Keyring, error) {
	kr := &Keyring{
		path: path,
		auth: auth,
	}
	return kr, nil
}

// Auth returns auth db.
func (k *Keyring) Auth() *auth.DB {
	return k.auth
}

// Status for vault.
type Status string

// Status of vault.
const (
	Locked      Status = "locked"
	Unlocked    Status = "unlocked"
	SetupNeeded Status = "setup-needed"
)

// Status returns vault status.
func (k *Keyring) Status() Status {
	if _, err := os.Stat(k.path); os.IsNotExist(err) {
		return SetupNeeded
	}
	if k.db == nil {
		return Locked
	}
	return Unlocked
}

// Setup vault.
// Doesn't unlock.
func (k *Keyring) Setup(mk *[32]byte) error {
	logger.Debugf("Setup...")
	if k.db != nil {
		return errors.Errorf("already unlocked")
	}
	if _, err := os.Stat(k.path); err == nil {
		return errors.Errorf("already setup")
	}

	// This creates a new db file (and on error we'll remove it).
	db, err := openDB(k.path, mk)
	if err != nil {
		return err
	}
	onErrFn := func() {
		_ = db.Close()
		_ = os.Remove(k.path)
	}

	if err := initTables(db); err != nil {
		onErrFn()
		return err
	}

	k.db = db

	logger.Debugf("Setup complete")
	return nil
}

// Unlock vault.
func (k *Keyring) Unlock(mk *[32]byte) error {
	logger.Debugf("Unlock...")

	if k.db != nil {
		logger.Debugf("Already unlocked")
		return nil
	}

	if _, err := os.Stat(k.path); os.IsNotExist(err) {
		return ErrSetupNeeded
	}

	db, err := openDB(k.path, mk)
	if err != nil {
		return err
	}
	onErrFn := func() {
		_ = db.Close()
	}

	if err := initTables(db); err != nil {
		onErrFn()
		return err
	}

	k.db = db

	logger.Debugf("Unlocked")
	return nil
}

// Lock vault.
func (k *Keyring) Lock() error {
	logger.Debugf("Locking...")

	if k.db == nil {
		logger.Debugf("Already locked")
		return nil
	}
	db := k.db
	k.db = nil

	if err := db.Close(); err != nil {
		return errors.Wrapf(err, "failed to close db")
	}

	return nil
}

// DB returns underlying database if vault is open.
// Returns nil if locked.
func (k *Keyring) DB() *sqlx.DB {
	if k.db == nil {
		return nil
	}
	return k.db
}

func (k *Keyring) Reset() error {
	return errors.Errorf("not implemented")
}

func (k *Keyring) initTables() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS keys (
			id TEXT PRIMARY KEY NOT NULL,
			type TEXT NOT NULL,
			private BLOB,
			public BLOB,
			createdAt INTEGER,
			updatedAt INTEGER,
			notes TEXT,
			labels TEXT,
			ext JSON
		);`,
		// TODO: Indexes
	}
	for _, stmt := range stmts {
		if _, err := k.db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (k *Keyring) initDB() error {
	if k.db == nil {
		return ErrLocked
	}
	if err := k.initTables(); err != nil {
		return err
	}
	return nil
}

// Set a key in the Keyring.
// Requires Unlock.
func (k *Keyring) Set(key *api.Key) error {
	if err := k.initDB(); err != nil {
		return err
	}
	return Transact(k.db, func(tx *sqlx.Tx) error {
		logger.Debugf("Saving key %s", key.ID)
		if err := updateKeyTx(tx, key); err != nil {
			return err
		}
		return nil
	})
}

// Remove a key.
// Requires Unlock.
func (k *Keyring) Remove(kid keys.ID) error {
	if err := k.initDB(); err != nil {
		return err
	}
	return Transact(k.db, func(tx *sqlx.Tx) error {
		return deleteKeyTx(tx, kid)
	})
}

// Keys in vault.
func (k *Keyring) Keys() ([]*api.Key, error) {
	if k.db == nil {
		return nil, ErrLocked
	}
	return getKeys(k.db)
}

// KeysWithType in vault.
func (k *Keyring) KeysWithType(typ string) ([]*api.Key, error) {
	if err := k.initDB(); err != nil {
		return nil, err
	}
	return getKeysByType(k.db, typ)
}

// KeysWithLabel in vault.
func (k *Keyring) KeysWithLabel(label string) ([]*api.Key, error) {
	if err := k.initDB(); err != nil {
		return nil, err
	}
	return getKeysByLabel(k.db, label)
}

// KeyWithLabel in vault.
func (k *Keyring) KeyWithLabel(label string) (*api.Key, error) {
	if err := k.initDB(); err != nil {
		return nil, err
	}
	ks, err := getKeysByLabel(k.db, label)
	if err != nil {
		return nil, err
	}
	if len(ks) == 0 {
		return nil, nil
	}
	if len(ks) > 1 {
		return nil, errors.Errorf("multiple keys for label %q", label)
	}
	return ks[0], nil
}

// Get key by id.
// Returns nil if not found.
func (k *Keyring) Get(kid keys.ID) (*api.Key, error) {
	if err := k.initDB(); err != nil {
		return nil, err
	}
	return getKey(k.db, kid)
}

// Key by id.
// If not found, returns keys.ErrNotFound.
// You can use Get instead.
func (k *Keyring) Key(kid keys.ID) (*api.Key, error) {
	if err := k.initDB(); err != nil {
		return nil, err
	}
	key, err := getKey(k.db, kid)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, keys.NewErrNotFound(kid.String())
	}
	return key, nil
}

func updateKeyTx(tx *sqlx.Tx, key *api.Key) error {
	logger.Debugf("Update key %s", key.ID)
	if _, err := tx.NamedExec(`INSERT OR REPLACE INTO keys VALUES 
		(:id, :type, :private, :public, :createdAt, :updatedAt, :notes, :labels, :ext)`, key); err != nil {
		return err
	}
	return nil
}

func deleteKeyTx(tx *sqlx.Tx, kid keys.ID) error {
	if kid == "" {
		return errors.Errorf("failed to delete key: empty id")
	}
	logger.Debugf("Deleting key %s", kid)
	if _, err := tx.Exec(`DELETE FROM keys WHERE id = ?`, kid); err != nil {
		return err
	}
	return nil
}

func getKey(db *sqlx.DB, kid keys.ID) (*api.Key, error) {
	var key api.Key
	if err := db.Get(&key, "SELECT * FROM keys WHERE id = $1", kid); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &key, nil
}

func getKeys(db *sqlx.DB) ([]*api.Key, error) {
	var vks []*api.Key
	if err := db.Select(&vks, "SELECT * FROM keys ORDER BY id"); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return vks, nil
}

func getKeysByType(db *sqlx.DB, typ string) ([]*api.Key, error) {
	var vks []*api.Key
	if err := db.Select(&vks, "SELECT * FROM keys WHERE type = $1 ORDER BY id", typ); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return vks, nil
}

func getKeysByLabel(db *sqlx.DB, label string) ([]*api.Key, error) {
	logger.Debugf("Get keys with label %q", label)
	var out []*api.Key
	sqlLabel := "%^" + label + "$%"
	if err := db.Select(&out, "SELECT * FROM keys WHERE labels LIKE $1", sqlLabel); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return out, nil
}
