//go:build appengine

package rabaead

import "reflect"

func anyOverlap(x, y []byte) bool {
	return len(x) > 0 && len(y) > 0 &&
		reflect.ValueOf(&x[0]).Pointer() <= reflect.ValueOf(&y[len(y)-1]).Pointer() &&
		reflect.ValueOf(&y[0]).Pointer() <= reflect.ValueOf(&x[len(x)-1]).Pointer()
}

func inexactOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {
		return false
	}
	return anyOverlap(x, y)
}
