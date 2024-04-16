// test is an static http server that serves the files in the current directory.
//
// Usage:
//
//	test [flags]
//
// Flags:
//
//	-c, --config string   sets custom configuration path
//	-h, --help            help for test
//
// Global Flags:
//
//	-v, --verbose   sets log level to debug
package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/securecookie"
	"github.com/urfave/cli/v2"
)

func main() {
	var hashKey = securecookie.GenerateRandomKey(64)
	var blockKey = securecookie.GenerateRandomKey(32)
	var s = securecookie.New(hashKey, blockKey)
	app := &cli.App{
		Name:  "test",
		Usage: "test is an static http server that serves the files in the current directory.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "sets custom configuration path",
			},
		},
		Action: func(c *cli.Context) error {
			// set the secure cookie

			http.Handle("/", http.FileServer(http.Dir(".")))
			fmt.Println("Serving files in the current directory on http://localhost:8080")
			return http.ListenAndServe(":8080", nil)
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
