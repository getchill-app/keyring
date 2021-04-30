package keyring

import (
	"encoding/hex"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"

	// For sqlite3 (sqlcipher driver)
	_ "github.com/mutecomm/go-sqlcipher/v4"
)

func openDB(path string, mk *[32]byte) (*sqlx.DB, error) {
	keyString := hex.EncodeToString(mk[:])
	pragma := fmt.Sprintf("?_pragma_key=x'%s'&_pragma_cipher_page_size=4096", keyString)

	db, err := sqlx.Open("sqlite3", path+pragma)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open db")
	}

	return db, nil
}

func initTables(db *sqlx.DB) error {
	logger.Debugf("Initializing tables...")
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS config (
			key TEXT PRIMARY KEY NOT NULL,
			value TEXT NOT NULL
		);`,
		// TODO: Indexes
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

// Transact creates and executes a transaction.
func Transact(db *sqlx.DB, txFn func(*sqlx.Tx) error) (err error) {
	if db == nil {
		return errors.Errorf("db not open")
	}
	tx, err := db.Beginx()
	if err != nil {
		return
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p) // Re-throw panic after Rollback
		} else if err != nil {
			_ = tx.Rollback() // err is non-nil; don't change it
		} else {
			err = tx.Commit() // err is nil; returns Commit error
		}
	}()
	err = txFn(tx)
	return err
}
