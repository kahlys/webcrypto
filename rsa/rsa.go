package rsa

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/gopherjs/gopherjs/js"
	"github.com/kahlys/webcrypto"
)

func importPrivateKey(prv *rsa.PrivateKey, alg, algname string, usages []string) (*js.Object, error) {
	jwkKey := js.M{
		"kty": "RSA",
		"alg": alg,
		"n":   base64.RawURLEncoding.EncodeToString(prv.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(prv.E)).Bytes()),
		"d":   base64.RawURLEncoding.EncodeToString(prv.D.Bytes()),
		"ext": true,
	}
	algorithm := js.M{
		"name": algname,
		"hash": map[string]string{"name": "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
	}
	return webcrypto.Call("importKey", "jwk", jwkKey, algorithm, false, usages)
}

func importPublicKey(pub *rsa.PublicKey, alg, algname string, usages []string) (*js.Object, error) {
	jwkKey := js.M{
		"kty": "RSA",
		"alg": alg,
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		"ext": true,
	}
	algorithm := js.M{
		"name": algname,
		"hash": map[string]string{"name": "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
	}
	return webcrypto.Call("importKey", "jwk", jwkKey, algorithm, false, usages)
}

// SignPKCS1 calculates the signature of msg using RSASSA-PKCS1-v1_5. The opts argument may be nil, in which case sensible
// defaults are used. Warning, msg will be hashed with SHA-256.
func SignPKCS1(priv *rsa.PrivateKey, msg []byte) ([]byte, error) {
	privKey, err := importPrivateKey(priv, "RS256", "RSASSA-PKCS1-v1_5", []string{"sign"})
	if err != nil {
		return nil, err
	}
	algorithm := js.M{
		"name": "RSASSA-PKCS1-v1_5",
	}
	resj, err := webcrypto.Call("sign", algorithm, privKey, msg)
	if err != nil {
		return nil, err
	}
	return js.Global.Get("Uint8Array").New(resj).Interface().([]byte), nil
}

// VerifyPKCS1 verifies the signature sig of msg using the public key pub. A valid signature is
// indicated by returning a nil error.
func VerifyPKCS1(pub *rsa.PublicKey, sig, msg []byte) error {
	pubKey, _ := importPublicKey(pub, "RS256", "RSASSA-PKCS1-v1_5", []string{"verify"})
	algorithm := js.M{
		"name": "RSASSA-PKCS1-v1_5",
	}
	resj, err := webcrypto.Call("verify", algorithm, pubKey, sig, msg)
	if err != nil {
		return err
	}
	if !resj.Bool() {
		return fmt.Errorf("verification error")
	}
	return nil
}

// SignPSS calculates the signature of msg using RSA-PSS. The opts argument may be nil, in which case sensible
// defaults are used. Warning, msg will be hashed with SHA-256. Salt length is 128.
func SignPSS(priv *rsa.PrivateKey, msg []byte) ([]byte, error) {
	privKey, err := importPrivateKey(priv, "PS256", "RSA-PSS", []string{"sign"})
	if err != nil {
		return nil, err
	}
	algorithm := js.M{
		"name":       "RSA-PSS",
		"saltLength": 128,
	}
	resj, err := webcrypto.Call("sign", algorithm, privKey, msg)
	if err != nil {
		return nil, err
	}
	return js.Global.Get("Uint8Array").New(resj).Interface().([]byte), nil
}

// VerifyPSS verifies the signature sig of msg using the public key pub. A valid signature is
// indicated by returning a nil error.
func VerifyPSS(pub *rsa.PublicKey, sig, msg []byte) error {
	pubKey, _ := importPublicKey(pub, "PS256", "RSA-PSS", []string{"verify"})
	algorithm := js.M{
		"name":       "RSA-PSS",
		"saltLength": 128,
	}
	resj, err := webcrypto.Call("verify", algorithm, pubKey, sig, msg)
	if err != nil {
		return err
	}
	if !resj.Bool() {
		return fmt.Errorf("verification error")
	}
	return nil
}

// EncryptOAEP encrypts a msg using RSA-OAEP.
func EncryptOAEP(pub *rsa.PublicKey, msg []byte) ([]byte, error) {
	key, err := importPublicKey(pub, "RSA-OAEP-256", "RSA-OAEP", []string{"encrypt"})
	if err != nil {
		return nil, err
	}
	algorithm := js.M{
		"name": "RSA-OAEP",
	}
	resj, err := webcrypto.Call("encrypt", algorithm, key, msg)
	if err != nil {
		return nil, err
	}
	return js.Global.Get("Uint8Array").New(resj).Interface().([]byte), nil
}

// DecryptOAEP decrypts a msg using RSA-OAEP.
func DecryptOAEP(priv *rsa.PrivateKey, msg []byte) ([]byte, error) {
	key, err := importPrivateKey(priv, "RSA-OAEP-256", "RSA-OAEP", []string{"decrypt"})
	if err != nil {
		return nil, err
	}
	algorithm := js.M{
		"name": "RSA-OAEP",
	}
	resj, err := webcrypto.Call("decrypt", algorithm, key, msg)
	if err != nil {
		return nil, err
	}
	return js.Global.Get("Uint8Array").New(resj).Interface().([]byte), nil
}
