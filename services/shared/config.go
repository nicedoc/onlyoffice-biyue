package shared

import (
	"context"
	"os"
	"time"

	"github.com/sethvargo/go-envconfig"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v2"
)

type IntegrationCredentials struct {
	Credentials struct {
		ClientID     string   `yaml:"client_id" env:"CREDENTIALS_CLIENT_ID"`
		ClientSecret string   `yaml:"client_secret" env:"CREDENTIALS_CLIENT_SECRET"`
		RedirectURL  string   `yaml:"redirect_url" env:"CREDENTIALS_REDIRECT_URL"`
		AuthURL      string   `yaml:"auth_url" env:"CREDENTIALS_AUTH_URL"`
		TokenURL     string   `yaml:"token_url" env:"CREDENTIALS_TOKEN_URL"`
		Scopes       []string `yaml:"scopes" env:"CREDENTIALS_SCOPES"`
	} `yaml:"credentials"`
}

func (ic *IntegrationCredentials) Validate() error {
	if ic.Credentials.ClientID == "" {
		return &InvalidConfigurationParameterError{
			Parameter: "ClientID",
			Reason:    "Should not be empty",
		}
	}

	if ic.Credentials.ClientSecret == "" {
		return &InvalidConfigurationParameterError{
			Parameter: "Client Secret",
			Reason:    "Should not be empty",
		}
	}

	return nil
}

func BuildNewIntegrationCredentialsConfig(path string) func() (*oauth2.Config, error) {
	return func() (*oauth2.Config, error) {
		var config IntegrationCredentials
		if path != "" {
			file, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			defer file.Close()

			decoder := yaml.NewDecoder(file)

			if err := decoder.Decode(&config); err != nil {
				return nil, err
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if err := envconfig.Process(ctx, &config); err != nil {
			return nil, err
		}

		return &oauth2.Config{
			ClientID:     config.Credentials.ClientID,
			ClientSecret: config.Credentials.ClientSecret,
			RedirectURL:  config.Credentials.RedirectURL,
			Scopes:       config.Credentials.Scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  config.Credentials.AuthURL,
				TokenURL: config.Credentials.TokenURL,
			},
		}, nil
	}
}

type OnlyofficeConfig struct {
	Onlyoffice struct {
		Builder  OnlyofficeBuilderConfig  `yaml:"builder"`
		Callback OnlyofficeCallbackConfig `yaml:"callback"`
	} `yaml:"onlyoffice"`
}

func (oc *OnlyofficeConfig) Validate() error {
	if err := oc.Onlyoffice.Builder.Validate(); err != nil {
		return err
	}

	return oc.Onlyoffice.Callback.Validate()
}

func BuildNewOnlyofficeConfig(path string) func() (*OnlyofficeConfig, error) {
	return func() (*OnlyofficeConfig, error) {
		var config OnlyofficeConfig
		config.Onlyoffice.Callback.MaxSize = 20000000
		config.Onlyoffice.Callback.UploadTimeout = 120
		config.Onlyoffice.Builder.AllowedDownloads = 10
		if path != "" {
			file, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			defer file.Close()

			decoder := yaml.NewDecoder(file)

			if err := decoder.Decode(&config); err != nil {
				return nil, err
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if err := envconfig.Process(ctx, &config); err != nil {
			return nil, err
		}

		return &config, config.Validate()
	}
}

type OnlyofficeBuilderConfig struct {
	DocumentServerURL    string `yaml:"document_server_url" env:"ONLYOFFICE_DS_URL,overwrite"`
	DocumentServerSecret string `yaml:"document_server_secret" env:"ONLYOFFICE_DS_SECRET,overwrite"`
	DocumentServerHeader string `yaml:"document_server_header" env:"ONLYOFFICE_DS_HEADER,overwrite"`
	GatewayURL           string `yaml:"gateway_url" env:"ONLYOFFICE_GATEWAY_URL,overwrite"`
	CallbackURL          string `yaml:"callback_url" env:"ONLYOFFICE_CALLBACK_URL,overwrite"`
	AllowedDownloads     int    `yaml:"allowed_downloads" env:"ONLYOFFICE_ALLOWED_DOWNLOADS,overwrite"`
}

func (oc *OnlyofficeBuilderConfig) Validate() error {
	return nil
}

type OnlyofficeCallbackConfig struct {
	MaxSize       int64 `yaml:"max_size" env:"ONLYOFFICE_CALLBACK_MAX_SIZE,overwrite"`
	UploadTimeout int   `yaml:"upload_timeout" env:"ONLYOFFICE_CALLBACK_UPLOAD_TIMEOUT,overwrite"`
}

func (c *OnlyofficeCallbackConfig) Validate() error {
	return nil
}

type S3Config struct {
	S3 struct {
		Bucket    string `yaml:"bucket" env:"S3_BUCKET"`
		Region    string `yaml:"region" env:"S3_REGION"`
		Url       string `yaml:"url" env:"S3_URL"`
		AccessKey string `yaml:"access_key" env:"S3_ACCESS_KEY"`
		SecretKey string `yaml:"secret_key" env:"S3_SECRET_KEY"`
		Api       string `yaml:"api" env:"S3_API"`
		Path      string `yaml:"path" env:"S3_PATH"`
	} `yaml:"s3"`
}

func (sc *S3Config) Validate() error {
	if sc.S3.Url == "" {
		return &InvalidConfigurationParameterError{
			Parameter: "s3 URL",
			Reason:    "Should not be empty",
		}
	}

	return nil
}

func BuildNewS3Config(path string) func() (*S3Config, error) {
	return func() (*S3Config, error) {
		var config S3Config
		if path != "" {
			file, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			defer file.Close()

			decoder := yaml.NewDecoder(file)

			if err := decoder.Decode(&config); err != nil {
				return nil, err
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if err := envconfig.Process(ctx, &config); err != nil {
			return nil, err
		}

		return &config, config.Validate()
	}
}
