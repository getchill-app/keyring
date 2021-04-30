package keyring

import (
	"github.com/getchill-app/keyring/auth"
	"github.com/keys-pub/keys"
)

// SetupPaperKey setup vault with a paper key.
func (k *Keyring) SetupPaperKey(paperKey string) (*[32]byte, error) {
	mk := keys.Rand32()
	_, err := k.auth.RegisterPaperKey(paperKey, mk)
	if err != nil {
		return nil, err
	}
	if err := k.Setup(mk); err != nil {
		return nil, err
	}
	return mk, nil
}

// RegisterPaperKey adds a paper key.
func (k *Keyring) RegisterPaperKey(mk *[32]byte, paperKey string) (*auth.Auth, error) {
	if k.db == nil {
		return nil, ErrLocked
	}
	reg, err := k.auth.RegisterPaperKey(paperKey, mk)
	if err != nil {
		return nil, err
	}
	return reg, nil
}

// UnlockWithPaperKey opens vault with a paper key.
func (k *Keyring) UnlockWithPaperKey(paperKey string) (*[32]byte, error) {
	_, mk, err := k.auth.PaperKey(paperKey)
	if err != nil {
		return nil, err
	}
	if err := k.Unlock(mk); err != nil {
		return nil, err
	}
	return mk, nil
}
