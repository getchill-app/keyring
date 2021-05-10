package main

import (
	"log"

	"github.com/getchill-app/keyring"
	"github.com/getchill-app/keyring/auth"
)

func main() {
	logger := keyring.NewLogger(keyring.DebugLevel)
	keyring.SetLogger(logger)

	auth, err := auth.NewDB("/tmp/auth.db")
	if err != nil {
		log.Fatal(err)
	}
	defer auth.Close()

	kr := keyring.New("/tmp/keyring.db", auth)
	if _, err := kr.SetupPassword("testpassword"); err != nil {
		log.Fatal(err)
	}

	if _, err := kr.UnlockWithPassword("testpassword"); err != nil {
		log.Fatal(err)
	}
	defer kr.Lock()
}
