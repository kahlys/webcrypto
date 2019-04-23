package ecdsa

import (
	"crypto/ecdsa"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/gopherjs/gopherjs/js"
	"github.com/kahlys/webcrypto"
)

func importPrivateKey(prv *ecdsa.PrivateKey) (*js.Object, error) {
	jwkKey := js.M{
		"kty": "EC",
		"crv": prv.Params().Name,
		"x":   base64.RawURLEncoding.EncodeToString(prv.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(prv.Y.Bytes()),
		"d":   base64.RawURLEncoding.EncodeToString(prv.D.Bytes()),
		"ext": true,
	}
	algorithm := js.M{
		"name":       "ECDSA",
		"namedCurve": prv.Params().Name,
	}
	return webcrypto.Call("importKey", "jwk", jwkKey, algorithm, false, []string{"sign"})
}

func importPublicKey(pub *ecdsa.PublicKey) (*js.Object, error) {
	jwkKey := js.M{
		"kty": "EC",
		"crv": pub.Params().Name,
		"x":   base64.RawURLEncoding.EncodeToString(pub.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(pub.Y.Bytes()),
		"ext": true,
	}
	algorithm := js.M{
		"name":       "ECDSA",
		"namedCurve": pub.Params().Name,
	}
	return webcrypto.Call("importKey", "jwk", jwkKey, algorithm, false, []string{"verify"})
}

type ecdsaSignature struct {
	R, S *big.Int
}

// Sign calculates the signature of msg using ECDSA. The opts argument may be nil, in which case sensible
// defaults are used. Warning, msg will be hashed with SHA-256. It returns asn1.encode(r.Bytes(), s.Bytes()).
func Sign(priv *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	privKey, err := importPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	hash := js.M{
		"name": "SHA-256",
	}
	algorithm := js.M{
		"name": "ECDSA",
		"hash": hash,
	}
	resj, err := webcrypto.Call("sign", algorithm, privKey, msg)
	if err != nil {
		return nil, err
	}
	res := js.Global.Get("Uint8Array").New(resj).Interface().([]byte)
	order := len(priv.Params().P.Bytes())
	r := new(big.Int).SetBytes(res[:order])
	s := new(big.Int).SetBytes(res[order:])
	return asn1.Marshal(ecdsaSignature{r, s})
}

// Verify verifies the signature sig of msg using the public key pub. A valid signature is
// indicated by returning a nil error.
func Verify(pub *ecdsa.PublicKey, sig, msg []byte) error {
	pubKey, _ := importPublicKey(pub)
	ss := new(ecdsaSignature)
	_, err := asn1.Unmarshal(sig, ss)
	if err != nil {
		return err
	}

	// slice size must be group order
	ssR, ssS := ss.R.Bytes(), ss.S.Bytes()
	order := len(pub.Params().P.Bytes())
	for len(ssR) < order {
		ssR = append([]byte{0}, ssR...)
	}
	for len(ssS) < order {
		ssS = append([]byte{0}, ssS...)
	}
	theSig := append(ssR, ssS...)

	hash := js.M{
		"name": "SHA-256",
	}
	algorithm := js.M{
		"name": "ECDSA",
		"hash": hash,
	}
	resj, err := webcrypto.Call("verify", algorithm, pubKey, theSig, msg)
	if err != nil {
		return err
	}
	if !resj.Bool() {
		return fmt.Errorf("verification error")
	}
	return nil
}
