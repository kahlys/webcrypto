package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/kahlys/webcrypto/aes"
	wecdsa "github.com/kahlys/webcrypto/ecdsa"
	"github.com/kahlys/webcrypto/sha"
)

func testSha1() error {
	expected, _ := hex.DecodeString("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed")
	actual, err := sha.Sum1([]byte("hello world"))
	if err != nil {
		return fmt.Errorf("sum1 error: %s", err)
	}
	if bytes.Compare(expected, actual) != 0 {
		return fmt.Errorf("not expected value")
	}
	return nil
}

func testSha256() error {
	expected, _ := hex.DecodeString("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
	actual, err := sha.Sum256([]byte("hello world"))
	if err != nil {
		return fmt.Errorf("sum256 error: %s", err)
	}
	if bytes.Compare(expected, actual) != 0 {
		return fmt.Errorf("not expected value")
	}
	return nil
}

func testSha384() error {
	expected, _ := hex.DecodeString("fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd")
	actual, err := sha.Sum384([]byte("hello world"))
	if err != nil {
		return fmt.Errorf("sum384 error: %s", err)
	}
	if bytes.Compare(expected, actual) != 0 {
		return fmt.Errorf("not expected value")
	}
	return nil
}

func testSha512() error {
	expected, _ := hex.DecodeString("309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f")
	actual, err := sha.Sum512([]byte("hello world"))
	if err != nil {
		return fmt.Errorf("sum512 error: %s", err)
	}
	if bytes.Compare(expected, actual) != 0 {
		return fmt.Errorf("not expected value")
	}
	return nil
}

func testAesCbc() error {
	expected, _ := hex.DecodeString("3647f8768f5198c9c60d1c2ce248b463290fe64907d38b339f649b9beb12e133")
	data := []byte("yellow submarine")
	iv, _ := hex.DecodeString("52cbbf25804213a7cdecfef9d22dac30")
	key, _ := hex.DecodeString("f4a08eef65d0be7082c2f7dcef2b9439")
	actual, err := aes.EncryptCBC(key, iv, data)
	if err != nil {
		return fmt.Errorf("encryption error: %s", err)
	}
	if bytes.Compare(expected, actual) != 0 {
		return fmt.Errorf("not expected ciphertext value")
	}
	actual, err = aes.DecryptCBC(key, iv, actual)
	if err != nil {
		return fmt.Errorf("encryption error: %s", err)
	}
	if bytes.Compare(data, actual) != 0 {
		return fmt.Errorf("not expected plaintext value")
	}
	return nil
}

func testAesGcm() error {
	// expected, _ := hex.DecodeString("TBD")
	data := []byte("yellow submarine")
	iv, _ := hex.DecodeString("52cbbf25804213a7cdecfef9d22dac30")
	key, _ := hex.DecodeString("f4a08eef65d0be7082c2f7dcef2b9439")
	actual, err := aes.EncryptGCM(key, iv, data, nil)
	if err != nil {
		return fmt.Errorf("encryption error: %s", err)
	}
	// if bytes.Compare(expected, actual) != 0 {
	// 	return fmt.Errorf("not expected ciphertext value")
	// }
	actual, err = aes.DecryptGCM(key, iv, actual, nil)
	if err != nil {
		return fmt.Errorf("encryption error: %s", err)
	}
	if bytes.Compare(data, actual) != 0 {
		return fmt.Errorf("not expected plaintext value")
	}
	return nil
}

func testEcdsa() error {
	text := []byte("yellow submarine")
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sig, err := wecdsa.Sign(priv, text)
	if err != nil {
		return fmt.Errorf("unable to sign: %v", err)
	}
	err = wecdsa.Verify(&priv.PublicKey, sig, text)
	if err != nil {
		return fmt.Errorf("unable to verify: %v", err)
	}
	return nil
}

func main() {
	register(
		testfunc{"SHA-1", testSha1},
		testfunc{"SHA-256", testSha256},
		testfunc{"SHA-384", testSha384},
		testfunc{"SHA-512", testSha512},
		testfunc{"AES-CBC", testAesCbc},
		testfunc{"AES-GCM", testAesGcm},
		testfunc{"ECDSA", testEcdsa},
	)
	run()
}

type testfunc struct {
	name string
	test func() error
}

var testset []testfunc

func register(tests ...testfunc) {
	testset = append(testset, tests...)
}

func run() {
	status := "SUCCESS"
	for _, t := range testset {
		fmt.Println("==", t.name)
		if err := t.test(); err != nil {
			fmt.Println(err)
			status = "FAILED"
		}
	}
	fmt.Printf("\nTESTS STATUS: %s\n", status)
}
