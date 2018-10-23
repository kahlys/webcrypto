package sha

import (
	"fmt"

	"github.com/gopherjs/gopherjs/js"
	"github.com/kahlys/webcrypto"
)

// Sum1 returns the SHA-1 of the data
func Sum1(data []byte) (res []byte, err error) {
	return sum("SHA-1", data)
}

// Sum256 returns the SHA-256 of the data
func Sum256(data []byte) (res []byte, err error) {
	return sum("SHA-256", data)
}

// Sum384 returns the SHA-384 of the data
func Sum384(data []byte) (res []byte, err error) {
	return sum("SHA-384", data)
}

// Sum512 returns the SHA-512 of the data
func Sum512(data []byte) (res []byte, err error) {
	return sum("SHA-512", data)
}

func sum(hash string, data []byte) (res []byte, err error) {
	algorithm := js.M{
		"name": hash,
	}
	resjs, err := webcrypto.Call("digest", algorithm, data)
	if err != nil {
		return nil, fmt.Errorf("unable to hash: %s", err)
	}
	return js.Global.Get("Uint8Array").New(resjs).Interface().([]byte), nil
}
