package keyring

import (
	"context"

	"github.com/getchill-app/keyring/auth"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys-ext/auth/fido2"
	"github.com/pkg/errors"
)

// SetFIDO2Plugin sets the plugin.
func (k *Keyring) SetFIDO2Plugin(fido2Plugin fido2.FIDO2Server) {
	k.fido2Plugin = fido2Plugin
}

// FIDO2Plugin if set.
func (k *Keyring) FIDO2Plugin() fido2.FIDO2Server {
	return k.fido2Plugin
}

// FIDO2Devices lists FIDO2 devices.
func (k *Keyring) FIDO2Devices(ctx context.Context) ([]*fido2.Device, error) {
	if k.fido2Plugin == nil {
		return nil, errors.Errorf("no fido2 plugin set")
	}
	resp, err := k.fido2Plugin.Devices(ctx, &fido2.DevicesRequest{})
	if err != nil {
		return nil, err
	}
	return resp.Devices, nil
}

// GenerateFIDO2HMACSecret ...
func (k *Keyring) GenerateFIDO2HMACSecret(ctx context.Context, pin string, device string, appName string) (*auth.FIDO2HMACSecret, error) {
	if k.fido2Plugin == nil {
		return nil, errors.Errorf("no fido2 plugin set")
	}
	return auth.GenerateFIDO2HMACSecret(ctx, k.fido2Plugin, pin, device, appName)
}

// SetupFIDO2HMACSecret sets up vault with a FIDO2 hmac-secret.
func (k *Keyring) SetupFIDO2HMACSecret(ctx context.Context, hs *auth.FIDO2HMACSecret, pin string) (*[32]byte, error) {
	if k.fido2Plugin == nil {
		return nil, errors.Errorf("no fido2 plugin set")
	}
	mk := keys.Rand32()
	_, err := k.auth.RegisterFIDO2HMACSecret(ctx, k.fido2Plugin, hs, mk, pin)
	if err != nil {
		return nil, err
	}
	if err := k.Setup(mk); err != nil {
		return nil, err
	}
	return mk, nil
}

// RegisterFIDO2HMACSecret adds vault with a FIDO2 hmac-secret.
// Requires recent Unlock.
func (k *Keyring) RegisterFIDO2HMACSecret(ctx context.Context, mk *[32]byte, hs *auth.FIDO2HMACSecret, pin string) (*auth.Auth, error) {
	if k.db == nil {
		return nil, ErrLocked
	}
	if k.fido2Plugin == nil {
		return nil, errors.Errorf("no fido2 plugin set")
	}
	reg, err := k.auth.RegisterFIDO2HMACSecret(ctx, k.fido2Plugin, hs, mk, pin)
	if err != nil {
		return nil, err
	}
	return reg, nil
}

// UnlockWithFIDO2HMACSecret opens vault with a FIDO2 hmac-secret.
func (k *Keyring) UnlockWithFIDO2HMACSecret(ctx context.Context, pin string) (*[32]byte, error) {
	_, mk, err := k.auth.FIDO2HMACSecret(ctx, k.fido2Plugin, pin)
	if err != nil {
		return nil, err
	}
	if err := k.Unlock(mk); err != nil {
		return nil, err
	}
	return mk, nil
}
