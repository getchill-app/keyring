package main

import (
	"context"
	"fmt"
	"log"

	"github.com/getchill-app/keyring"
	"github.com/getchill-app/keyring/auth"
	"github.com/keys-pub/keys-ext/auth/fido2"
)

func main() {
	logger := keyring.NewLogger(keyring.DebugLevel)
	keyring.SetLogger(logger)

	// FIDO2
	fido2Plugin, err := fido2.OpenPlugin("fido2.so")
	if err != nil {
		log.Fatal(err)
	}

	// Auth
	auth, err := auth.NewDB("/tmp/auth.db")
	if err != nil {
		log.Fatal(err)
	}
	defer auth.Close()

	// Keyring
	kr, err := keyring.New("/tmp/keyring.db", auth)
	if err != nil {
		log.Fatal(err)
	}
	kr.SetFIDO2Plugin(fido2Plugin)

	pin := "12345"

	// Generate
	fmt.Println("Generating FIDO2 hmac-secret...")
	hs, err := kr.GenerateFIDO2HMACSecret(context.TODO(), pin, "", "getchill.app/examples")
	if err != nil {
		log.Fatal(err)
	}

	// Setup
	fmt.Println("Setting up with FIDO2 hmac-secret...")
	if _, err := kr.SetupFIDO2HMACSecret(context.TODO(), hs, pin); err != nil {
		log.Fatal(err)
	}

	// Unlock
	fmt.Println("Unlocking with FIDO2 hmac-secret...")
	if _, err := kr.UnlockWithFIDO2HMACSecret(context.TODO(), pin); err != nil {
		log.Fatal(err)
	}
	defer kr.Lock()

}
