# webcrypto

![stability-wip](https://img.shields.io/badge/stability-work_in_progress-lightgrey.svg)
[![GoDoc](https://godoc.org/github.com/kahlys/webcrypto?status.svg)](https://godoc.org/github.com/kahlys/webcrypto)
[![Go Report Card](https://goreportcard.com/badge/github.com/kahlys/webcrypto)](https://goreportcard.com/report/github.com/kahlys/webcrypto)

Golang wrapper around the WebCryptoAPI.

## Installation

With a correctly configured [Go toolchain](https://golang.org/doc/install):

```
$ go get -u github.com/gopherjs/gopherjs
$ go get -u github.com/kahlys/webcrypto
```

## Testing

Go to the test directory, compile using gopherjs, then open `test.html` with a browser and look results at the console.

```
$ cd test
$ gopherjs build test.go
```

## Packages

- [SHA](https://godoc.org/github.com/kahlys/webcrypto/sha) : [sha-1](https://godoc.org/github.com/kahlys/webcrypto/sha#Sum1) | [sha-256](https://godoc.org/github.com/kahlys/webcrypto/sha#Sum256) | [sha-384](https://godoc.org/github.com/kahlys/webcrypto/sha#Sum384) | [sha-512](https://godoc.org/github.com/kahlys/webcrypto/sha#Sum512)
- [AES](https://godoc.org/github.com/kahlys/webcrypto/aes) : [cbc](https://godoc.org/github.com/kahlys/webcrypto/aes#EncryptCBC) | [gcm](https://godoc.org/github.com/kahlys/webcrypto/aes#EncryptGCM)
- [ECDSA](https://godoc.org/github.com/kahlys/webcrypto/ecdsa)
