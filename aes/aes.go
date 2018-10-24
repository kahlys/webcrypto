package aes

import (
	"github.com/gopherjs/gopherjs/js"
	"github.com/kahlys/webcrypto"
)

// importKey imports aes key for a given mode, and return a js object to use. The extractable boolean set if the key can be export.
func importKey(mode string, key []byte) (*js.Object, error) {
	algorithm := js.M{
		"name": mode,
	}
	return webcrypto.Call("importKey", "raw", key, algorithm, false, []string{"encrypt", "decrypt"})
}

// EncryptCBC performs an aes-cbc encryption. A default padding is added to the plaintext by the webcryptoapi, according to RFC2315-10.3.
func EncryptCBC(key, iv, text []byte) ([]byte, error) {
	k, err := importKey("AES-CBC", key)
	if err != nil {
		return nil, err
	}
	algorithm := js.M{
		"name": "AES-CBC",
		"iv":   iv,
	}
	resjs, err := webcrypto.Call("encrypt", algorithm, k, text)
	if err != nil {
		return nil, err
	}
	return js.Global.Get("Uint8Array").New(resjs).Interface().([]byte), nil
}

// DecryptCBC performs an aes-cbc decryption.
func DecryptCBC(key, iv, text []byte) ([]byte, error) {
	k, err := importKey("AES-CBC", key)
	if err != nil {
		return nil, err
	}
	algorithm := js.M{
		"name": "AES-CBC",
		"iv":   iv,
	}
	resjs, err := webcrypto.Call("decrypt", algorithm, k, text)
	if err != nil {
		return nil, err
	}
	return js.Global.Get("Uint8Array").New(resjs).Interface().([]byte), nil
}
