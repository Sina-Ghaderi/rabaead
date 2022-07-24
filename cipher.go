package rabaead

import (
	"crypto/cipher"
	"errors"

	"github.com/sina-ghaderi/poly1305"
	"github.com/sina-ghaderi/rabbitio"
)

const polykeylen = 0x20 // poly1305 key len: 32byte

var ErrAuthMsg = errors.New("rabaead: message authentication failed")
var erroverlap = errors.New("rabaead: invalid buffer memory overlap")

type rabbitPoly1305 struct {
	key       []byte // rabbit cipher key
	noncesize int    // rabbit iv size
}

// NewAEAD returns a rabbit aead data-type
// key must be 16 byte len
func NewAEAD(key []byte) (cipher.AEAD, error) { return newRabbitAead(key) }

func newRabbitAead(key []byte) (cipher.AEAD, error) {
	if len(key) != rabbitio.KeyLen {
		return nil, rabbitio.ErrInvalidKey
	}

	rabbitAead := &rabbitPoly1305{
		noncesize: rabbitio.IVXLen,
		key:       make([]byte, rabbitio.KeyLen),
	}
	copy(rabbitAead.key[:], key)
	return rabbitAead, nil

}

// Overhead returns poly1305 tag size: 16byte
func (c *rabbitPoly1305) Overhead() int { return poly1305.TagSize }

// NonceSize returns rabbit iv len: 8byte
func (c *rabbitPoly1305) NonceSize() int { return c.noncesize }

func (c *rabbitPoly1305) sealRabbit(dst, nonce, plaintext, ad []byte) []byte {
	ret, out := headtail(dst, len(plaintext)+poly1305.TagSize)
	ciphertext, tag := out[:len(plaintext)], out[len(plaintext):]
	if inexactOverlap(out, plaintext) {
		panic(erroverlap) //should never happen
	}

	var polyKey [polykeylen]byte
	s, err := rabbitio.NewCipher(c.key, nonce)
	if err != nil {
		panic(err)
	}
	s.XORKeyStream(polyKey[:], polyKey[:])
	p := poly1305.New(&polyKey)
	writePadding(p, ad)

	s, err = rabbitio.NewCipher(c.key, nonce)
	if err != nil {
		panic(err)
	}
	s.XORKeyStream(ciphertext, plaintext)

	writePadding(p, ciphertext)

	writeUint64(p, len(ad))
	writeUint64(p, len(plaintext))
	p.Sum(tag[:0x00])

	return ret
}

func (c *rabbitPoly1305) openRabbit(dst, nonce, ciphertext, ad []byte) ([]byte, error) {
	tag := ciphertext[len(ciphertext)-poly1305.TagSize:]
	ciphertext = ciphertext[:len(ciphertext)-poly1305.TagSize]

	var polyKey [polykeylen]byte
	s, err := rabbitio.NewCipher(c.key, nonce)
	if err != nil {
		panic(err)
	}
	s.XORKeyStream(polyKey[:], polyKey[:])

	p := poly1305.New(&polyKey)
	writePadding(p, ad)
	writePadding(p, ciphertext)

	writeUint64(p, len(ad))
	writeUint64(p, len(ciphertext))

	ret, out := headtail(dst, len(ciphertext))
	if inexactOverlap(out, ciphertext) {
		panic(erroverlap) //should never happen
	}

	// check data integrity
	if !p.Verify(tag) {
		return nil, ErrAuthMsg
	}

	s, err = rabbitio.NewCipher(c.key, nonce)
	if err != nil {
		panic(err)
	}
	s.XORKeyStream(out, ciphertext)
	return ret, nil
}

// Open opens a rabbit aead ciphertext.
// panic occurs if nonce len is not equal to IVXLen (8byte) or zero
// if data is not verified, ErrAuthMsg will be returned
func (c *rabbitPoly1305) Open(dst, nonce, ciphertext, ad []byte) ([]byte, error) {

	if len(ciphertext) < poly1305.TagSize {
		return nil, ErrAuthMsg
	}

	return c.openRabbit(dst, nonce, ciphertext, ad)
}

// Seal seals a plaintext into the rabbit aead ciphertext.
// panic occurs if nonce len is not equal to IVXLen (8byte) or zero
func (c *rabbitPoly1305) Seal(dst, nonce, plaintext, ad []byte) []byte {
	return c.sealRabbit(dst, nonce, plaintext, ad)
}
