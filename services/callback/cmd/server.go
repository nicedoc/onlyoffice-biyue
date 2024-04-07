 package cmd

 import (
	 "fmt"
 
	 "github.com/nicedoc/onlyoffice-biyue/services/callback/web"
	 "github.com/nicedoc/onlyoffice-biyue/services/callback/web/controller"
	 "github.com/nicedoc/onlyoffice-biyue/services/shared"
	 "github.com/nicedoc/onlyoffice-biyue/services/shared/client"
	 pkg "github.com/ONLYOFFICE/onlyoffice-integration-adapters"
	 chttp "github.com/ONLYOFFICE/onlyoffice-integration-adapters/service/http"
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
					 chttp.NewService, web.NewServer,
					 shared.BuildNewOnlyofficeConfig(configPath),
					 shared.BuildNewIntegrationCredentialsConfig(configPath),
					 controller.NewCallbackController,
					 client.NewDropboxAuthClient,
				 ),
			 ).Bootstrap()
 
			 if err := app.Err(); err != nil {
				 return fmt.Errorf("could not bootstrap an http server: %w", err)
			 }
 
			 app.Run()
 
			 return nil
		 },
	 }
 }