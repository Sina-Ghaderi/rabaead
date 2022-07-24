package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"snix.ir/rabaead"
	"snix.ir/rabbitio"
)

func main() {
	encFlag := flag.NewFlagSet("encrypt", flag.ExitOnError)
	decFlag := flag.NewFlagSet("decrypt", flag.ExitOnError)
	flag.Usage = flagUsage
	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		server(encFlag)
	case "client":
		client(decFlag)
	default:
		flag.Usage()
		os.Exit(1)
	}
}

func flagUsage() {

	fmt.Printf(`usage of %v: commands <args...|help>
commands:

   server <args...>     encrypt files with rabbit poly1305 aead cipher
   client <args...>     decrypt files with rabbit poly1305 aead cipher


Copyright (c) 2022 snix.ir, All rights reserved.
Developed BY <Sina Ghaderi> sina@snix.ir
This work is licensed under the terms of GNU General Public license.
Github: github.com/sina-ghaderi and Source: git.snix.ir
`, os.Args[0])
}

func server(flagset *flag.FlagSet) {

	plain := flagset.String("net", "127.0.0.1:7899", "network tcp listen address")
	keyva := flagset.String("key", "", "rabbit key string, must be 16-byte len")
	ivxva := flagset.String("ivx", "", "rabbit iv string, must be 8-byte or nothing")
	flagset.Parse(os.Args[2:])

	ivb := []byte(*ivxva)

	if len(ivb) != rabbitio.IVXLen && len(ivb) != 0 {
		log.Fatal(rabbitio.ErrInvalidIVX)
	}

	aead, err := rabaead.NewAEAD([]byte(*keyva))
	if err != nil {
		log.Fatal(err)
	}

	l, err := net.Listen("tcp", *plain)
	if err != nil {
		log.Fatal(err)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Print(err)
			continue
		}

		writer, _ := rabaead.NewChunkWriter(conn, 16, aead, ivb, nil)
		go handleServerConn(writer, conn)
	}

}

func handleServerConn(w io.WriteCloser, conn net.Conn) {
	defer conn.Close()
	if _, err := w.Write([]byte(time.Now().String())); err != nil {
		log.Print(err)
		return
	}
}

func client(flagset *flag.FlagSet) {
	plain := flagset.String("net", "127.0.0.1:7899", "network tcp dial address")
	keyva := flagset.String("key", "", "rabbit key string, must be 16-byte len")
	ivxva := flagset.String("ivx", "", "rabbit iv string, must be 8-byte or nothing")
	flagset.Parse(os.Args[2:])

	ivb := []byte(*ivxva)

	aead, err := rabaead.NewAEAD([]byte(*keyva))
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.Dial("tcp", *plain)
	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()

	reader, err := rabaead.NewChunkReader(conn, 16, aead, ivb, nil)
	if err != nil {
		log.Fatal(err)
	}

	ntms := []byte{}
	buff := make([]byte, 16)

	for {
		n, err := reader.Read(buff)
		if err != nil {
			if err == io.EOF {
				ntms = append(ntms, buff[:n]...)
				break
			}
			log.Fatal(err)
		}
		ntms = append(ntms, buff...)
	}

	log.Printf("server time: %v", string(ntms))

}
