package rabaead

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"io"

	"snix.ir/rabbitio"
)

const cmrk = 0x04 // chunk size indicator,
// without this reader cannot calculate actual size of plaintext

// additional data func, return value is used as AD in Seal and Open
// nil AdFunc is harmless and equal to func()[]byte{return nil}
type AdditionalFunc func() []byte

type chunkReader struct {
	aead  cipher.AEAD
	csize int
	rader io.Reader
	buff  []byte
	nonce []byte
	adexe AdditionalFunc
}

type chunkWriter struct {
	aead   cipher.AEAD
	csize  int
	writer io.Writer
	buff   []byte
	nonce  []byte
	adexe  AdditionalFunc
}

// NewChunkReader returns a chunkReader data type, this reader reads and open() aead
// ciphertext, each chunk has its own tag and cmrk value.
// this reader has a chunk size in-memory buffer, large chunk size can make application to runs
// out of memory, thus is most suitable for sliced data, like network data transmit and so..
func NewChunkReader(r io.Reader, chnk uint32, a cipher.AEAD, nonce []byte, f AdditionalFunc) (*chunkReader, error) {

	if len(nonce) != rabbitio.IVXLen && len(nonce) != 0 {
		return nil, rabbitio.ErrInvalidIVX
	}

	s := &chunkReader{
		aead:  a,
		buff:  []byte{},
		nonce: make([]byte, len(nonce)),
		csize: int(chnk),
		rader: r,
		adexe: f,
	}

	if s.adexe == nil {
		s.adexe = func() []byte { return nil }
	}
	copy(s.nonce, nonce)
	return s, nil
}

// NewChunkWriter returns a chunkWriter data type, this writer sale() and write aead
// plaintext, each chunk has its own tag and cmrk value.
// this writer has a chunk size in-memory buffer, large chunk size can make application to
// runs out of memory, thus is most suitable for sliced data, like network data transmit and so..
func NewChunkWriter(w io.Writer, chnk uint32, a cipher.AEAD, nonce []byte, f AdditionalFunc) (*chunkWriter, error) {

	if len(nonce) != rabbitio.IVXLen && len(nonce) != 0 {
		return nil, rabbitio.ErrInvalidIVX
	}
	s := &chunkWriter{
		aead:   a,
		buff:   []byte{},
		nonce:  make([]byte, len(nonce)),
		csize:  int(chnk),
		writer: w,
		adexe:  f,
	}

	if s.adexe == nil {
		s.adexe = func() []byte { return nil }
	}

	copy(s.nonce, nonce)
	return s, nil
}

// Close method, if there is any
func (w *chunkWriter) Close() error {
	if c, ok := w.writer.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// Write writes plaintext chunk into the sale() and underlying writer
// write would not report overhead data (chunk size marker and poly1305 tag) in
// written return value. for each chunk there is 4+16 byte overhead data.
// AdFunc will be triggered for each chunk of data
func (w *chunkWriter) Write(b []byte) (n int, err error) {
	w.buff = b
	for len(w.buff) > 0 {
		s, err := w.write()
		if err != nil {
			return n, err
		}
		n += s
	}
	return
}

func (w *chunkWriter) write() (int, error) {
	size := cmrk + w.csize + w.aead.Overhead()
	chnk := make([]byte, size)
	var n int
	var err error

	if len(w.buff) > 0 {
		s := copy(chnk[cmrk:len(chnk)-w.aead.Overhead()], w.buff)
		w.buff = w.buff[s:]
		copy(chnk[0:cmrk], uint32Little(uint32(s)))

		w.aead.Seal(chnk[:0], w.nonce, chnk[:cmrk+w.csize], w.adexe())
		_, err = w.writer.Write(chnk)
		if err != nil {
			return n, err
		}
		n += s
	}

	return n, err
}

// Read reads and open() ciphertext chunk from underlying reader
// read would not report overhead data (chunk size marker and poly1305 tag) in its
// return value. if the read data from underlying reader is corrupted, ErrAuthMsg
// error will be returned. for each chunk there is 4+16 byte overhead data.
// AdFunc will be triggered for each chunk of data

func (r *chunkReader) Read(b []byte) (int, error) {
	if len(b) <= r.csize {
		return r.readTo(b)
	}
	n := 0
	for {
		if n+r.csize > len(b) {
			sr, err := r.readTo(b[n:])
			n += sr
			if err != nil {
				return n, err
			}
			break
		}
		sr, err := r.readTo(b[n : n+r.csize])
		n += sr
		if err != nil {
			return n, err
		}
	}

	return n, nil
}

func (r *chunkReader) readTo(b []byte) (int, error) {
	var n int
	if len(r.buff) > 0 {
		n = copy(b, r.buff)
		r.buff = r.buff[n:]
		return n, nil
	}

	sr, err := r.read()
	n = copy(b, r.buff[:sr])
	r.buff = r.buff[n:]
	return n, err
}

func (r *chunkReader) read() (int, error) {

	var n int
	size := cmrk + r.csize + r.aead.Overhead()
	chnk := make([]byte, size)
	chLE := uint32Little(uint32(r.csize))

	si, err := io.ReadFull(r.rader, chnk)
	if err != nil {
		return n, err
	}

	if si > 0 {
		_, err = r.aead.Open(chnk[:0], r.nonce, chnk, r.adexe())
		if err != nil {
			return n, err
		}

		if bytes.Equal(chnk[0:cmrk], chLE) {
			n += r.csize
			r.buff = append(r.buff, chnk[cmrk:cmrk+r.csize]...)
		} else {
			f := binary.LittleEndian.Uint32(chnk[0:cmrk])
			n += int(f)
			r.buff = append(r.buff, chnk[cmrk:cmrk+f]...)
		}
	}

	return n, err
}

func uint32Little(n uint32) []byte {
	b := make([]byte, cmrk)
	binary.LittleEndian.PutUint32(b, n)
	return b
}
