package main

import (
	"log"

	"github.com/nicedoc/onlyoffice-biyue/services/callback/cmd"
)

func main() {
	if err := cmd.Run(); err != nil {
		log.Fatalln(err)
	}
}