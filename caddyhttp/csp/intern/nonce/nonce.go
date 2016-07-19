package nonce

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
)

var pool = &sync.Pool{New: func() interface{} {
	return &noncePool{buf: make([]byte, 256)}
}}

// New efficiently generates a Base64 encoded nonce value (128 bit) for use in CSP.
//
// "The generated value SHOULD be at least 128 bits long (before encoding), [...]"
// This implementation uses 128 bits, as this is more than enough and is easily
// amortizable.
// See https://www.w3.org/TR/2015/CR-CSP2-20150219/#source-list-syntax

// CSP uses base64 standard alphabet, see
// https://www.w3.org/TR/2015/CR-CSP2-20150219/#base64_value
func New() string {
	r := pool.Get().(*noncePool)
	n := r.nonce()
	pool.Put(r)

	return n
}

// noncePool reads random bytes in bulk and delivers chunks of it. This amortizes
// syscalls. On slow Linux machines this saves about 30% time (inclusive base64 encoding
// in nonce()). On faster machines the time savings are not as pronounced. Windows
// experiences a 500% boost on a slow machine.
// See http://blog.sgmansfield.com/2016/06/managing-syscall-overhead-with-crypto-rand/
type noncePool struct {
	count uint64
	buf   []byte
}

func (r *noncePool) nonce() string {
	const width = 16
	window := r.count % width
	r.count++
	if window == 0 {
		_, err := rand.Read(r.buf)
		if err != nil {
			panic(err)
		}
	}
	start, end := window*width, (window+1)*width

	return base64.StdEncoding.EncodeToString(r.buf[start:end])
}
