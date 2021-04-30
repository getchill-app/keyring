package keyring

import (
	"github.com/getchill-app/keyring/auth"
	"github.com/keys-pub/keys"
)

// SetupPassword setup vault with a password.
func (k *Keyring) SetupPassword(password string) (*[32]byte, error) {
	mk := keys.Rand32()
	if _, err := k.auth.RegisterPassword(password, mk); err != nil {
		return nil, err
	}
	if err := k.Setup(mk); err != nil {
		return nil, err
	}
	return mk, nil
}

// RegisterPassword adds a password.
func (k *Keyring) RegisterPassword(mk *[32]byte, password string) (*auth.Auth, error) {
	if k.db == nil {
		return nil, ErrLocked
	}
	reg, err := k.auth.RegisterPassword(password, mk)
	if err != nil {
		return nil, err
	}
	return reg, nil
}

// UnlockWithPassword opens vault with a password.
func (k *Keyring) UnlockWithPassword(password string) (*[32]byte, error) {
	_, mk, err := k.auth.Password(password)
	if err != nil {
		return nil, err
	}
	if err := k.Unlock(mk); err != nil {
		return nil, err
	}
	return mk, nil
}
