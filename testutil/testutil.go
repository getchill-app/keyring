package testutil

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/keys-pub/keys"
)

// Path ...
func Path() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("%s.db", keys.RandFileName()))
}

// Seed ...
func Seed(b byte) *[32]byte {
	return keys.Bytes32(bytes.Repeat([]byte{b}, 32))
}
