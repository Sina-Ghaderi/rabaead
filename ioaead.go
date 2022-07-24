package rabaead

import (
	"crypto/cipher"
	"errors"
	"io"

	"github.com/sina-ghaderi/poly1305"
	"github.com/sina-ghaderi/rabbitio"
)

type streamReader struct {
	ie        *ioaead
	cip       cipher.Stream
	firstRead bool
	nwr       int
	read      io.Reader
	buff      []byte
	temp      []byte
	tagc      []byte
}

type ioaead struct {
	key            []byte // rabbit cipher key
	nonce          []byte
	poly           *poly1305.MAC
	adlen          int
	additionalData AdditionalFunc
}

type streamWriter struct {
	ie          *ioaead
	writer      io.Writer
	plainWriter io.Writer
	nwr         int
	firstWrite  bool
}

var errunderio = errors.New("underlying io reader returns wrong read value, which is not supposed to happen")

func makeioaead(key, iv []byte, adfunc AdditionalFunc) *ioaead {
	if adfunc == nil {
		adfunc = func() []byte { return nil }
	}
	str := &ioaead{
		key:   make([]byte, rabbitio.KeyLen),
		nonce: make([]byte, len(iv)),
	}

	str.additionalData = adfunc
	copy(str.key, key)
	copy(str.nonce, iv)
	var poly [polykeylen]byte
	cph, _ := rabbitio.NewCipher(str.key, str.nonce)
	cph.XORKeyStream(poly[:], poly[:])
	str.poly = poly1305.New(&poly)
	return str
}

func (s *ioaead) execAdFunc() {
	additionalData := s.additionalData()
	s.adlen = len(additionalData)
	writePadding(s.poly, additionalData)
}

func newCipherReader(r io.Reader, key, nonce []byte, f AdditionalFunc) (*streamReader, error) {
	if len(key) != rabbitio.KeyLen {
		return nil, rabbitio.ErrInvalidKey
	}

	if len(nonce) != rabbitio.IVXLen && len(nonce) != 0 {
		return nil, rabbitio.ErrInvalidIVX
	}

	v := &streamReader{
		ie:   makeioaead(key, nonce, f),
		read: r,
		buff: []byte{},
		tagc: make([]byte, 16),
		temp: make([]byte, 16),
	}

	v.cip, _ = rabbitio.NewCipher(v.ie.key, v.ie.nonce)
	return v, nil
}

// NewStreamReader returns streamReader data type, this reader open() and read aead
// ciphertext which have 16-byte poly1305 tag overhead.
// read data cannot be authenticated until underlying reader returns EOF
// so you should use this reader only if you can undo your read.
// AdFunc will be triggered at first call to read method
func NewStreamReader(r io.Reader, key, nonce []byte, f AdditionalFunc) (*streamReader, error) {
	return newCipherReader(r, key, nonce, f)
}

// NewStreamWriter returns streamWriter data type, this writer sale() and write aead
// plaintext which have 16-byte poly1305 tag overhead, running Close() is necessary
// in order to calculate and write tag at the end of the write.
// AdFunc will be triggered at first call to write method
func NewStreamWriter(w io.Writer, key, nonce []byte, f AdditionalFunc) (*streamWriter, error) {
	return newChipherWriter(w, key, nonce, f)
}

func newChipherWriter(w io.Writer, key, nonce []byte, f AdditionalFunc) (*streamWriter, error) {
	if len(key) != rabbitio.KeyLen {
		return nil, rabbitio.ErrInvalidKey
	}
	if len(nonce) != rabbitio.IVXLen && len(nonce) != 0 {
		return nil, rabbitio.ErrInvalidIVX
	}
	v := &streamWriter{
		ie:          makeioaead(key, nonce, f),
		plainWriter: w,
	}

	v.writer, _ = rabbitio.NewWriterCipher(
		v.ie.key, v.ie.nonce,
		io.MultiWriter(w, v.ie.poly),
	)

	return v, nil
}

func (r *streamReader) readTo(b []byte) (int, error) {
	var n int
	if len(r.buff) > 0 {
		return r.copyBuff(b), nil
	}

	sr, err := r.readBuff()
	if err != nil {
		if err == io.EOF {
			n = r.copyUntil(b, sr)
			return n, r.verify()
		}
		return n, err
	}
	return r.copyUntil(b, sr), err
}

// Read reads and open ciphertext.
// read data is unreliable until underlying reader returns EOF
// after that Read return EOF or ErrAuthMsg if integrity of data has been compromised.
// in such a case, you need to unread data. a simple demonstration would be to delete
// or truncate the file if ErrAuthMsg is returned
func (r *streamReader) Read(b []byte) (int, error) {
	if len(b) <= 16 {
		return r.readTo(b)
	}
	n := 0
	for {
		if n+16 > len(b) {
			sr, err := r.readTo(b[n:])
			n += sr
			if err != nil {
				return n, err
			}
			break
		}

		sr, err := r.readTo(b[n : n+16])
		n += sr
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func (r *streamReader) verify() error {
	r.ie.ioPaddingTo(r.nwr)
	if r.ie.poly.Verify(r.tagc) {
		return io.EOF
	}
	return ErrAuthMsg
}

func (r *streamReader) copyUntil(b []byte, sr int) int {
	n := copy(b, r.buff[:sr])
	r.buff = r.buff[n:]
	r.nwr += n
	return n
}

func (r *streamReader) copyBuff(b []byte) int {
	n := copy(b, r.buff)
	r.buff = r.buff[n:]
	r.nwr += n
	return n
}

func (r *streamReader) readBuff() (int, error) {
	if !r.firstRead {
		r.ie.execAdFunc()
		_, err := io.ReadFull(r.read, r.temp)
		if err != nil {
			return 0, err
		}
		r.firstRead = true
	}

	var buff = make([]byte, 16)
	n, err := r.read.Read(buff)
	if err != nil {
		return 0, err
	}
	if n > len(buff) {
		return 0, errunderio
	}

	copy(r.tagc, append(r.temp[n:], buff[:n]...))
	r.buff = append(r.buff, r.temp[:n]...)
	r.buffAndXor()

	if n < 16 {
		return n, err
	}

	copy(r.temp, buff)
	return n, err
}

func (r *streamReader) buffAndXor() {
	r.ie.poly.Write(r.buff)
	r.cip.XORKeyStream(r.buff, r.buff)
}

// Write writes plaintext data, in order to calculate and write tag
// at the end of the write, running Close() is necessary
func (w *streamWriter) Write(b []byte) (int, error) {
	if !w.firstWrite {
		w.ie.execAdFunc()
		w.firstWrite = true
	}
	n, err := w.writer.Write(b)
	if err != nil {
		return n, err
	}

	w.nwr += n
	return n, err
}

func (p *ioaead) ioPaddingTo(nb int) {
	if rem := nb % 16; rem != 0 {
		var buf [16]byte
		padLen := 16 - rem
		p.poly.Write(buf[:padLen])
	}

	writeUint64(p.poly, p.adlen)
	writeUint64(p.poly, nb)
}

// Close calculate and write poly1305 tag before closing the writer
// if underlying writer does not have a Close() method, Close only
// calculate and write poly1305 tag
func (w *streamWriter) Close() error {
	w.ie.ioPaddingTo(w.nwr)
	if _, err := w.plainWriter.Write(w.ie.poly.Sum(nil)); err != nil {
		return err
	}

	if c, ok := w.plainWriter.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
