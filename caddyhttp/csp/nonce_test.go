package csp

import (
	"encoding/base64"
	"testing"

	"github.com/mholt/caddy/caddyhttp/csp/intern/nonce"
)

func BenchmarkNewNonce(b *testing.B) {
	for i := 0; i < b.N; i++ {
		nonce.New()
	}
}

func TestNew(t *testing.T) {
	for i := 0; i < 1000; i++ {
		nonce := nonce.New()
		data, err := base64.StdEncoding.DecodeString(nonce)
		if err != nil {
			t.Error(err)
		}
		if l := len(data); l != 16 {
			t.Errorf("Want %d bytes, got %d.", 16, l)
		}
	}
}
