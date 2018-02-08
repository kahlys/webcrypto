package main

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/kahlys/webcrypto/sha"
)

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

func main() {
	register(
		testfunc{"SHA-256", testSha256},
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
