package cmd

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
)

func GetCommands() cli.Commands {
	return []*cli.Command{
		Server(),
	}
}

func Run() error {
	app := &cli.App{
		Name:        "onlyoffice:runner",
		Description: "Description",
		Authors: []*cli.Author{
			{
				Name:  "NiceDoc",
				Email: "support@nicedoc.cn",
			},
		},
		HideVersion: true,
		Commands:    GetCommands(),
	}

	if err := app.Run(os.Args); err != nil {
		return fmt.Errorf("could not start a service: %w", err)
	}

	return nil
}
