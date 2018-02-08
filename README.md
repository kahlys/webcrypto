# webcrypto

**WORK IN PROGRESS**

Golang wrapper around the WebCryptoAPI

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

- `sha`: `sha-256`
