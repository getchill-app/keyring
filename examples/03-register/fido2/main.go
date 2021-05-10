package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/davecgh/go-spew/spew"
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
	kr := keyring.New("/tmp/keyring.db", auth)
	kr.SetFIDO2Plugin(fido2Plugin)

	// Registering new auth method requires unlock
	mk, err := kr.UnlockWithPassword("testpassword")
	if err != nil {
		log.Fatal(err)
	}
	defer kr.Lock()

	pin := "12345"

	devices, err := kr.FIDO2Devices(context.TODO())
	if err != nil {
		log.Fatal(err)
	}
	if len(devices) == 0 {
		log.Fatal("no FIDO2 devices found")
	}
	fmt.Printf("Found %d device(s)\n", len(devices))
	device := devices[0].Path
	fmt.Printf("Using device: %s\n", device)

	// Generate
	fmt.Println("Generating FIDO2 hmac-secret...")
	hs, err := kr.GenerateFIDO2HMACSecret(context.TODO(), pin, device, "getchill.app/examples")
	if err != nil {
		log.Fatal(err)
	}

	// Register
	fmt.Println("Register FIDO2 hmac-secret...")
	reg, err := kr.RegisterFIDO2HMACSecret(context.TODO(), mk, hs, pin)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Registered: %s", spew.Sdump(reg))
}

func goBin(file string) string {
	out, err := exec.Command("go", "env", "GOPATH").Output()
	if err != nil {
		panic(err)
	}
	return filepath.Join(strings.TrimSpace(string(out)), "bin", file)
}
