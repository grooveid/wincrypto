package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"

	"github.com/grooveid/wincrypto"
)

func main() {
	decrypt := flag.Bool("d", false, "decrypt stdin")

	input, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal("cannot read input: %v", err)
	}

	var output []byte
	if *decrypt {
		output, err = wincrypto.UnprotectSecret(input)
		if err != nil {
			log.Fatal("cannot decrypt: %v", err)
		}
	} else {
		output, err = wincrypto.ProtectSecret(input)
		if err != nil {
			log.Fatal("cannot encrypt: %v", err)
		}
	}

	os.Stdout.Write(output)
}
