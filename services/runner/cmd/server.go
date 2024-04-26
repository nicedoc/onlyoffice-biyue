package cmd

import (
	"context"
	"fmt"

	pkg "github.com/ONLYOFFICE/onlyoffice-integration-adapters"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	chttp "github.com/ONLYOFFICE/onlyoffice-integration-adapters/service/http"
	"go.uber.org/fx"
	"golang.org/x/sync/errgroup"

	"github.com/urfave/cli/v2"
)

func Server() *cli.Command {
	return &cli.Command{
		Name:     "server",
		Usage:    "starts a new http server instance",
		Category: "server",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Category: "configuration",
				Name:     "config_path",
				Usage:    "sets custom configuration path",
				Aliases:  []string{"config", "conf", "c"},
			},
		},

		Action: func(c *cli.Context) error {
			var (
				configPath = c.String("config_path")
			)

			app := pkg.NewBootstrapper(
				configPath, pkg.WithModules(
					crypto.NewStateGenerator,
					BuildNewNsqConfig(configPath),
					BuildNewRunner,
					NewTaskController,
					chttp.NewService,
					BuildNewServer,
				),
				pkg.WithInvokables(func(lifecycle fx.Lifecycle, runner *Runner) {
					lifecycle.Append(fx.Hook{
						OnStart: func(ctx context.Context) error {
							go runner.Run()
							return nil
						},
						OnStop: func(ctx context.Context) error {
							g, gCtx := errgroup.WithContext(ctx)
							g.Go(func() error {
								return runner.Shutdown(gCtx)
							})
							return g.Wait()
						},
					})
				}),
			).Bootstrap()

			if err := app.Err(); err != nil {
				return fmt.Errorf("could not bootstrap an http server: %w", err)
			}

			app.Run()

			return nil
		},
	}
}
