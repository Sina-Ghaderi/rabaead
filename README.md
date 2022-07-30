# rabaead
rabbit128 poly1305 aead cipher package for golang, this package implement aead (authenticated encryption with associated data) cipher
with associated io chunk and io stream interfaces.

### aead methods:
- **seal**: seals a plaintext into the rabbit aead ciphertext. **panic** occurs if nonce len is not equal to IVXLen (8byte) or zero
- **open**: opens a rabbit aead ciphertext. **panic** occurs if nonce len is not equal to IVXLen (8byte) or zero

<p align="center">
   <img src="https://github.com/Sina-Ghaderi/rabaead/blob/master/seal.png" alt="seal"/>
</p>



### io interfaces:  
- **chunkReader**: read and open() data in chunks, there is 2byte + 16byte overhead per chunk. read data can be used safely. this reader has a chunk size in-memory buffer, large chunk size can make application to runs out of memory, thus this is most suitable for sliced data, like network data transmit and so..

- **chunkReader**: seal() and write data in chunks, there is 2byte + 16byte overhead per chunk. this writer has a chunk size in-memory buffer, large chunk size can make application to runs out of memory, thus this is most suitable for sliced data, like network data transmit and so..
<p align="center">
   <img src="https://github.com/Sina-Ghaderi/rabaead/blob/master/chunkio.png" alt="chunkio"/>
</p>

- **streamReader**: this reader open() and read aead ciphertext which have 16-byte poly1305 tag overhead. **read data is unreliable until underlying reader returns EOF**, after that Read return EOF or ErrAuthMsg if integrity of data has been compromised. in such a case, you need to unread data. a simple demonstration would be to delete or truncate the file if ErrAuthMsg is returned


- **streamWriter**: this writer seal() and write aead plaintext which have 16-byte poly1305 tag overhead, running Close() is necessary in order to calculate and write tag at the end of the write.


### how to use?
rabaead lives on both [github](github.com/sina-ghaderi/rabaead) and [snix](git.snix.ir/rabaead) git services, you can simply import this package 
by using either `import "snix.ir/rabaead"` or `import "github.com/sina-ghaderi/rabaead"`


### examples
check out [_example](_example) directory which contains real-world use cases of rabaead cipher, in addition you may want to look at test unit files or package [documentation](https://pkg.go.dev/github.com/sina-ghaderi/rabaead) at pkg.go.dev    

```go
// aead open() and seal() methods
func rabbitPoly1305() {
	key := []byte{
		0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01,
	}
	ivx := []byte{
		0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01,
	}
	buff := []byte("plain-text")
	aead, err := rabaead.NewAEAD(key)
	if err != nil {
		panic(err)
	}
	ctxt := aead.Seal([]byte{}, ivx, buff, nil)
	fmt.Printf("aead data: %x\n", ctxt)
	ptxt, err := aead.Open([]byte{}, ivx, ctxt, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("plaintext: %s\n", string(ptxt))
}

```

### licence and contribute
feel free to email me sina@snix.ir if you want to contribute to this project.
GNU General Public [License](LICENSE) v3





