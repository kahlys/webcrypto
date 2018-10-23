package sha

import (
	"fmt"

	"github.com/gopherjs/gopherjs/js"
)

// Sum1 returns the SHA-1 of the data
func Sum1(data []byte) (res []byte, err error) {
	return sum("SHA-1", data)
}

// Sum256 returns the SHA-256 of the data
func Sum256(data []byte) (res []byte, err error) {
	return sum("SHA-256", data)
}

func sum(hash string, data []byte) (res []byte, err error) {
	crypt := js.Global.Get("crypto")
	if crypt == js.Undefined {
		crypt = js.Global.Get("msCrypto")
	}
	crypto := crypt.Get("subtle")
	if crypto != js.Undefined {
		if crypto.Get("digest") != js.Undefined {
			resChan := make(chan []byte, 1)
			algorithm := js.M{
				"name": hash,
			}
			promise := crypto.Call("digest", algorithm, data)
			promise.Call("then", func(result *js.Object) {
				go func() {
					resChan <- js.Global.Get("Uint8Array").New(result).Interface().([]byte)
				}()
			})
			res = <-resChan
			return res, nil
		}
	}
	return nil, fmt.Errorf("webcrypto api error: unable to get js.crypto.subtle.digest or js.msCrypto.subtle.digest")
}
