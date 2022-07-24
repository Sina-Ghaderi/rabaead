### file encrypt
a simple tool to encrypt or decrypt files with rabbit poly1305 aead cipher, working on linux only. 
windows users can modify [main.go](_example/file_encrypt/main.go) file and remove [unlink()](https://man7.org/linux/man-pages/man2/unlink.2.html) syscall, then run `go build` to build the binary

usage encrypt: `./file_encrypt encrypt -key sina1234sina1234 -ivx abcd1234 -file plain.txt`  
usage decrypt: `./file_encrypt decrypt -key sina1234sina1234 -ivx abcd1234 -file enc_plain.txt`  



### secure conn
secure net transmit data with rabbit poly1305 aead cipher, execute `go build` to build the binary. server write its own time on client connection
encrypted with chunkWriter, and client reads cipherdata from connection with chunkReader  
server: `./secure_conn server -key sina1234sina1234 -ivx abcd1234 -net 127.0.0.1:7894`  
client: `./secure_conn client -key sina1234sina1234 -ivx abcd1234 -net 127.0.0.1:7894`
