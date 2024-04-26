package cmd

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/sethvargo/go-envconfig"
	"gopkg.in/yaml.v2"
)

type NsqAddrConfig struct {
	NsqLookupDS string `yaml:"nsq_lookupds" env:"BIYUE_NSQ_LOOKUPDS"`
	NsqAddress  string `yaml:"nsq_address" env:"BIYUE_NSQ_ADDRESS"`
	NsqTopic    string `yaml:"nsq_topic" env:"BIYUE_NSQ_TOPIC"`
	NsqChannel  string `yaml:"nsq_channel" env:"BIYUE_NSQ_CHANNEL"`
}

func (sc *NsqAddrConfig) Validate() error {
	if sc.NsqLookupDS == "" {
		return errors.New("nsq_lookupds should not be empty")
	}
	return nil
}

func BuildNewNsqConfig(path string) func() (*NsqAddrConfig, error) {
	return func() (*NsqAddrConfig, error) {
		var config NsqAddrConfig
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
