package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"golang.org/x/sys/unix"
	"snix.ir/rabaead"
)

const prefix = "enc_"

func main() {
	encFlag := flag.NewFlagSet("encrypt", flag.ExitOnError)
	decFlag := flag.NewFlagSet("decrypt", flag.ExitOnError)
	flag.Usage = flagUsage
	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "encrypt":
		encrypt(encFlag)
	case "decrypt":
		decrypt(decFlag)
	default:
		flag.Usage()
		os.Exit(1)
	}
}

func encrypt(flagset *flag.FlagSet) {
	plain := flagset.String("file", "plain.txt", "file to encrypt with RabbitPoly1305 aead")
	keyva := flagset.String("key", "", "rabbit key string, must be 16-byte len")
	ivxva := flagset.String("ivx", "", "rabbit iv string, must be 8-byte or nothing")
	flagset.Parse(os.Args[2:])

	file, err := os.Open(*plain)
	if err != nil {
		log.Fatal(err)
	}

	defer file.Close()

	dest, err := os.OpenFile(prefix+file.Name(), os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
	if err != nil {
		log.Fatal(err)
	}

	defer dest.Close()

	cipw, err := rabaead.NewStreamWriter(dest, []byte(*keyva), []byte(*ivxva), nil)
	if err != nil {
		log.Fatal(err)
	}

	n, err := io.Copy(cipw, file)
	if err != nil {
		log.Fatal(err)
	}

	// calc and write poly1305 tag at the end of write
	if err := cipw.Close(); err != nil {
		log.Fatal(err)
	}

	if err := unix.Unlink(file.Name()); err != nil {
		log.Printf("syscall unlink(): %v", err)
	}

	log.Printf("file %s encrypted to %s, bytes written: %d", file.Name(), dest.Name(), n)
}

func decrypt(flagset *flag.FlagSet) {
	dectx := flagset.String("file", "enc_plain.txt", "file to decrypt with RabbitPoly1305 aead")
	keyva := flagset.String("key", "", "rabbit key string, must be 16-byte len")
	ivxva := flagset.String("ivx", "", "rabbit iv string, must be 8-byte or nothing")
	flagset.Parse(os.Args[2:])

	file, err := os.Open(*dectx)
	if err != nil {
		log.Fatal(err)
	}

	defer file.Close()

	name := strings.TrimPrefix(file.Name(), prefix)

	dest, err := os.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
	if err != nil {
		log.Fatal(err)
	}

	defer dest.Close()

	cipr, err := rabaead.NewStreamReader(file, []byte(*keyva), []byte(*ivxva), nil)
	if err != nil {
		log.Fatal(err)
	}

	n, err := io.Copy(dest, cipr)
	if err != nil {
		if err := unix.Unlink(dest.Name()); err != nil {
			log.Printf("syscall unlink(): %v", err)
		}
		log.Fatal(err)
	}

	if err := unix.Unlink(file.Name()); err != nil {
		log.Printf("syscall unlink(): %v", err)
	}

	log.Printf("file %s encrypted to %s, bytes written: %d", file.Name(), dest.Name(), n)
}

func flagUsage() {
	fmt.Printf(`usage of %v: commands <args...|help>
commands:

   encrypt <args...>     encrypt files with rabbit poly1305 aead cipher
   decrypt <args...>     decrypt files with rabbit poly1305 aead cipher


Copyright (c) 2022 snix.ir, All rights reserved.
Developed BY <Sina Ghaderi> sina@snix.ir
This work is licensed under the terms of GNU General Public license.
Github: github.com/sina-ghaderi and Source: git.snix.ir
`, os.Args[0])
}
