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

// EncryptGCM performs an aes-gcm encryption. The 16 last bytes of the output is the tag.
func EncryptGCM(key, iv, text, extraData []byte) ([]byte, error) {
	k, err := importKey("AES-GCM", key)
	if err != nil {
		return nil, err
	}
	algorithm := js.M{
		"name":      "AES-GCM",
		"iv":        iv,
		"tagLength": 128,
	}
	if extraData != nil {
		algorithm["additionalData"] = extraData
	}
	resjs, err := webcrypto.Call("encrypt", algorithm, k, text)
	if err != nil {
		return nil, err
	}
	return js.Global.Get("Uint8Array").New(resjs).Interface().([]byte), nil
}

// DecryptGCM performs an aes-gcm decryption.
func DecryptGCM(key, iv, text, extraData []byte) ([]byte, error) {
	k, err := importKey("AES-GCM", key)
	if err != nil {
		return nil, err
	}
	algorithm := js.M{
		"name":      "AES-GCM",
		"iv":        iv,
		"tagLength": 128,
	}
	if extraData != nil {
		algorithm["additionalData"] = extraData
	}
	resjs, err := webcrypto.Call("decrypt", algorithm, k, text)
	if err != nil {
		return nil, err
	}
	return js.Global.Get("Uint8Array").New(resjs).Interface().([]byte), nil
}
