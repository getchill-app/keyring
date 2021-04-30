package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/getchill-app/keyring"
	"github.com/getchill-app/keyring/auth"
	"github.com/keys-pub/keys-ext/auth/fido2"
)

func main() {
	logger := keyring.NewLogger(keyring.DebugLevel)
	keyring.SetLogger(logger)

	// FIDO2
	fido2Plugin, err := fido2.OpenPlugin(goBin("fido2.so"))
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

	// Unlock
	fmt.Println("Unlocking with FIDO2 hmac-secret...")
	if _, err := kr.UnlockWithFIDO2HMACSecret(context.TODO(), pin); err != nil {
		log.Fatal(err)
	}
	defer kr.Lock()
}

func goBin(file string) string {
	out, err := exec.Command("go", "env", "GOPATH").Output()
	if err != nil {
		panic(err)
	}
	return filepath.Join(strings.TrimSpace(string(out)), "bin", file)
}
