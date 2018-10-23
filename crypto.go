package webcrypto

import (
	"fmt"

	"github.com/gopherjs/gopherjs/js"
)

var subtleCrypto *js.Object

func init() {
	crypto := new(js.Object)
	// default: crypto, IE: msCrypto
	for _, m := range []string{"crypto", "msCrypto"} {
		crypto = js.Global.Get(m)
		if crypto != js.Undefined {
			break
		}
	}
	if crypto == js.Undefined {
		return
	}
	subtle := new(js.Object)
	// default: subtle, safari: webkitSubtle
	for _, m := range []string{"subtle", "webkitSubtle"} {
		subtle = crypto.Get(m)
		if subtle != js.Undefined {
			break
		}
	}
	subtleCrypto = subtle
}

// Call calls the object's method with the given name and arguments.
func Call(method string, args ...interface{}) (res *js.Object, err error) {
	if subtleCrypto == nil {
		return nil, fmt.Errorf("unable to find js.crypto.subtle")
	}
	if subtleCrypto.Get(method) == js.Undefined {
		return nil, fmt.Errorf("unable to find js.crypto.subtle.%v", method)
	}
	chanRes := make(chan *js.Object, 1)
	chanErr := make(chan *js.Object, 1)
	promise := subtleCrypto.Call(method, args...)
	promise.Call(
		"then",
		func(res *js.Object) { chanRes <- res },
		func(err *js.Object) { chanErr <- err },
	)
	select {
	case jsres := <-chanRes:
		return jsres, nil
	case jserr := <-chanErr:
		return nil, fmt.Errorf("js error: %s", jserr.Get("name").String())
	}
}
