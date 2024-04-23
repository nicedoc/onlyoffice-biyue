/**
 *
 * (c) Copyright Ascensio System SIA 2023
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package cmd

import (
	"fmt"

	pkg "github.com/ONLYOFFICE/onlyoffice-integration-adapters"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	chttp "github.com/ONLYOFFICE/onlyoffice-integration-adapters/service/http"
	"github.com/nicedoc/onlyoffice-biyue/services/gateway/web"
	"github.com/nicedoc/onlyoffice-biyue/services/gateway/web/controller"
	"github.com/nicedoc/onlyoffice-biyue/services/gateway/web/controller/convert"
	"github.com/nicedoc/onlyoffice-biyue/services/gateway/web/middleware"
	"github.com/nicedoc/onlyoffice-biyue/services/shared"
	"github.com/nicedoc/onlyoffice-biyue/services/shared/client"
	"github.com/urfave/cli/v2"
)

func Server() *cli.Command {
	return &cli.Command{
		Name:     "server",
		Usage:    "starts a new http server instance",
		Category: "server",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config_path",
				Usage:   "sets custom configuration path",
				Aliases: []string{"config", "conf", "c"},
			},
		},
		Action: func(c *cli.Context) error {
			var (
				configPath = c.String("config_path")
			)

			app := pkg.NewBootstrapper(
				configPath, pkg.WithModules(
					crypto.NewStateGenerator,
					shared.BuildNewIntegrationCredentialsConfig(configPath),
					shared.BuildNewOnlyofficeConfig(configPath),
					shared.BuildNewBiyueConfig(configPath),
					controller.NewAuthController,
					controller.NewEditorController,
					convert.NewConvertController,
					middleware.NewSessionMiddleware,
					chttp.NewService, web.NewServer,
					client.NewMinioAuthClient,
				),
			).Bootstrap()

			if err := app.Err(); err != nil {
				return fmt.Errorf("could not bootstrap a server: %w", err)
			}

			app.Run()

			return nil
		},
	}
}
