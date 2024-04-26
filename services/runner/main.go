package main

import (
	"log"

	"github.com/nicedoc/onlyoffice-biyue/services/runner/cmd"
)

func main() {
	if err := cmd.Run(); err != nil {
		log.Fatalln(err)
	}
}
