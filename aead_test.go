package rabaead_test

import (
	"bytes"
	"io"
	"log"
	"testing"

	"github.com/sina-ghaderi/rabaead"
)

var key = []byte{
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
}

var iv = []byte{
	0xfa, 0xfa, 0xfa, 0xfa,
	0xfa, 0xfa, 0xfa, 0xfa,
}

var ptx = []byte{
	0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c,
	0x0d, 0x0e, 0x0f, 0x10,
}

// Simple AEAD Cipher Test
func TestNewAEAD(t *testing.T) {
	aead, err := rabaead.NewAEAD(key)
	if err != nil {
		t.Fatal(err)
	}

	bf := aead.Seal([]byte{}, iv, ptx, []byte{0x01, 0x01, 0x01, 0x01})
	t.Logf("aead encrypted: %x\n", bf)

	bf, err = aead.Open([]byte{}, iv, bf, []byte{0x01, 0x01, 0x01, 0x01})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("aead decrypted: %x\n", bf)

	if !bytes.Equal(bf, ptx) {
		t.Fatal("decrypted data is not same as plaintext")
	}
}

// TestChunkIO Encrypt and decrypt with NewChunkWriter and NewChunkReader
func TestChunkIO(t *testing.T) {
	buf := &bytes.Buffer{}
	aead, err := rabaead.NewAEAD(key)
	if err != nil {
		t.Fatal(err)
	}

	w, _ := rabaead.NewChunkWriter(buf, 0x08, aead, iv, nil)
	if _, err := w.Write(ptx); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	t.Logf("aead encrypted: %x\n", buf.Bytes())

	r, _ := rabaead.NewChunkReader(buf, 0x08, aead, iv, nil)
	pbf := make([]byte, 18)
	n, err := r.Read(pbf)
	if err != nil {
		if err != io.EOF {
			t.Fatal(err)
		}
	}

	t.Logf("aead decrypted: %x\n", pbf)
	if !bytes.Equal(pbf[:n], ptx) {
		t.Fatal("decrypted data is not same as plaintext")
	}
}

// test StreamWriter and Reader
func TestStreamIO(t *testing.T) {
	buf := &bytes.Buffer{}
	w, err := rabaead.NewStreamWriter(buf, key, iv, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := w.Write(ptx); err != nil {
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	t.Logf("aead encrypted: %x\n", buf.Bytes())

	r, err := rabaead.NewStreamReader(buf, key, iv, nil)
	if err != nil {
		t.Fatal(err)
	}

	pbf := make([]byte, 16)
	n, err := r.Read(pbf)
	if err != nil {
		if err != io.EOF {
			t.Fatal(err)
		}
	}
	t.Logf("aead decrypted: %x\n", pbf)
	if !bytes.Equal(pbf[:n], ptx) {
		t.Fatal("decrypted data is not same as plaintext")
	}
}

func TestStreamIO2(t *testing.T) {
	buf := &bytes.Buffer{}
	w, err := rabaead.NewStreamWriter(buf, key, iv, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := w.Write(ptx); err != nil {
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	t.Logf("aead encrypted: %x\n", buf.Bytes())

	r, err := rabaead.NewStreamReader(buf, key, iv, nil)
	if err != nil {
		t.Fatal(err)
	}

	pbf := make([]byte, 17)
	n, err := r.Read(pbf)
	if err != nil {
		if err != io.EOF {
			t.Fatal(err)
		}
	}

	t.Logf("aead decrypted: %x\n", pbf)
	if !bytes.Equal(pbf[:n], ptx) {
		t.Fatal("decrypted data is not same as plaintext")
	}
}

func TestStreamIO3(t *testing.T) {
	buf := &bytes.Buffer{}
	w, err := rabaead.NewStreamWriter(buf, key, iv, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := w.Write(ptx); err != nil {
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	t.Logf("aead encrypted: %x\n", buf.Bytes())

	r, err := rabaead.NewStreamReader(buf, key, iv, nil)
	if err != nil {
		t.Fatal(err)
	}

	pbf := make([]byte, 27)
	n, err := r.Read(pbf)
	if err != nil {
		if err != io.EOF {
			t.Fatal(err)
		}
	}
	t.Logf("aead decrypted: %x\n", pbf)
	if !bytes.Equal(pbf[:n], ptx) {
		t.Fatal("decrypted data is not same as plaintext")
	}
}

func TestStreamIO4(t *testing.T) {
	buf := &bytes.Buffer{}
	w, err := rabaead.NewStreamWriter(buf, key, iv, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := w.Write(ptx); err != nil {
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	t.Logf("aead encrypted: %x\n", buf.Bytes())

	r, err := rabaead.NewStreamReader(buf, key, iv, nil)
	if err != nil {
		t.Fatal(err)
	}

	pbf := make([]byte, 7)
	vsf := make([]byte, 0)
	for {
		n, err := r.Read(pbf)
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		vsf = append(vsf, pbf[:n]...)

	}
	t.Logf("aead decrypted: %x\n", vsf)
	if !bytes.Equal(vsf, ptx) {
		t.Fatal("decrypted data is not same as plaintext")
	}
}

func TestStreamIO5(t *testing.T) {
	buf := &bytes.Buffer{}
	w, err := rabaead.NewStreamWriter(buf, key, iv, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := w.Write(append(ptx, 0x02)); err != nil {
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	t.Logf("aead encrypted: %x\n", buf.Bytes())

	r, err := rabaead.NewStreamReader(buf, key, iv, nil)
	if err != nil {
		t.Fatal(err)
	}

	pbf := make([]byte, 7)
	vsf := make([]byte, 0)
	for {
		n, err := r.Read(pbf)
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		vsf = append(vsf, pbf[:n]...)

	}
	t.Logf("aead decrypted: %x\n", vsf)
	if !bytes.Equal(vsf, append(ptx, 0x02)) {
		t.Fatal("decrypted data is not same as plaintext")
	}
}

// TestIOAndAEAD encrypt a plaintext and opens with AEAD Open()
func TestIOAndAEAD(t *testing.T) {
	buf := &bytes.Buffer{}
	w, err := rabaead.NewStreamWriter(buf, key, iv, func() []byte { return []byte{0x01, 0x01, 0x01, 0x01} })
	if err != nil {
		t.Fatal(err)
	}

	if _, err := w.Write(ptx); err != nil {
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	t.Logf("aead encrypted: %x\n", buf.Bytes())
	aead, err := rabaead.NewAEAD(key)
	if err != nil {
		t.Fatal(err)
	}

	bf, err := aead.Open([]byte{}, iv, buf.Bytes(), []byte{0x01, 0x01, 0x01, 0x01})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("aead decrypted: %x\n", bf)
}

func TestChunkIOErr(t *testing.T) {
	buf := &bytes.Buffer{}
	aead, err := rabaead.NewAEAD(key)
	if err != nil {
		t.Fatal(err)
	}

	w, _ := rabaead.NewChunkWriter(buf, 0x08, aead, iv, nil)
	if _, err := w.Write(ptx); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	t.Logf("aead encrypted: %x\n", buf.Bytes())

	r, _ := rabaead.NewChunkReader(buf, 0x09, aead, iv, nil)
	pbf := make([]byte, 18)
	_, err = r.Read(pbf)

	t.Logf("aead decrypted: %x\n", pbf)
	if err != rabaead.ErrAuthMsg {
		t.Fatal("err auth must returned")
	}
}

func TestAEADAndIO(t *testing.T) {

	aead, err := rabaead.NewAEAD(key)
	if err != nil {
		t.Fatal(err)
	}

	bf := aead.Seal([]byte{}, iv, ptx, []byte{0x01, 0x01, 0x01, 0x01})

	buf := bytes.NewReader(bf)
	r, err := rabaead.NewStreamReader(buf, key, iv, func() []byte { return []byte{0x01, 0x01, 0x01, 0x01} })
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("aead encrypted: %x\n", bf)

	var sc = &bytes.Buffer{}
	_, err = io.Copy(sc, r)
	if err != nil {
		log.Fatal(err)
	}

	t.Logf("aead decrypted: %x\n", sc.Bytes())
}

func TestStreamIOErr(t *testing.T) {
	buf := &bytes.Buffer{}
	f := func() []byte { return []byte{0x01} }
	w, err := rabaead.NewStreamWriter(buf, key, iv, f)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := w.Write(ptx); err != nil {
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	t.Logf("aead encrypted: %x\n", buf.Bytes())

	r, err := rabaead.NewStreamReader(buf, key, iv, nil)
	if err != nil {
		t.Fatal(err)
	}

	pbf := make([]byte, 16)
	for {
		_, err = r.Read(pbf)
		if err != nil {
			break
		}
	}
	t.Logf("aead decrypted: %x\n", pbf)
	if err != rabaead.ErrAuthMsg {
		t.Fatal("err auth must returned")
	}
}
