package main

import (
	"fmt"
	"log"

	"github.com/getchill-app/keyring"
	"github.com/getchill-app/keyring/auth"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/keys/tsutil"
	"github.com/pkg/errors"
)

func main() {
	logger := keyring.NewLogger(keyring.DebugLevel)
	keyring.SetLogger(logger)

	auth, err := auth.NewDB("/tmp/auth.db")
	if err != nil {
		log.Fatal(err)
	}
	defer auth.Close()

	kr, err := keyring.New("/tmp/keyring.db", auth)
	if err != nil {
		log.Fatal(err)
	}

	if _, err := kr.UnlockWithPassword("testpassword"); err != nil {
		log.Fatal(errors.Wrapf(err, "failed to open vault"))
	}
	defer kr.Lock()

	test := api.NewKey(keys.GenerateEdX25519Key()).WithLabels("test").Created(tsutil.NowMillis())
	if err := kr.Set(test); err != nil {
		log.Fatal(err)
	}

	ks, err := kr.Keys()
	if err != nil {
		log.Fatal(err)
	}
	for _, key := range ks {
		fmt.Printf("%s %s %s\n", key.ID, tsutil.ParseMillis(key.CreatedAt), key.Labels)
	}
}
