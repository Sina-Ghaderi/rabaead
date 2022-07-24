package rabaead

import (
	"encoding/binary"

	"github.com/sina-ghaderi/poly1305"
)

func headtail(in []byte, n int) (head, tail []byte) {
	total := len(in) + n

	if cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

func writePadding(p *poly1305.MAC, b []byte) {
	p.Write(b)
	if rem := len(b) % 16; rem != 0 {
		var buf [16]byte
		padLen := 16 - rem
		p.Write(buf[:padLen])
	}
}

func writeUint64(p *poly1305.MAC, n int) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(n))
	p.Write(buf[:])
}
