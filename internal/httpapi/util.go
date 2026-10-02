package httpapi

import "crypto/rand"

func newRandomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("httpapi: cannot read crypto/rand: " + err.Error())
	}
	const hexchars = "0123456789abcdef"
	out := make([]byte, 64)
	for i, x := range b {
		out[i*2] = hexchars[x>>4]
		out[i*2+1] = hexchars[x&0x0f]
	}
	return string(out)
}
