package csp

import (
	"fmt"
	"testing"

	"github.com/mholt/caddy/caddyhttp/csp/intern/nonce"
)

func BenchmarkStringCat(b *testing.B) {
	bucket := make([]string, 0, b.N)
	nonce := nonce.New()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bucket = append(bucket, "'nonce-"+nonce+"'")
	}
}

func BenchmarkStringFormat(b *testing.B) {
	bucket := make([]string, 0, b.N)
	nonce := nonce.New()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bucket = append(bucket, fmt.Sprintf("'nonce-%s'", nonce))
	}
}
