package helper

import (
	"log"

	"github.com/spf13/viper"
)

var ServiceConfiguration Configuration

func init() {
	ServiceConfiguration = loadConfig(".")
}

func loadConfig(path string) Configuration {
	viper.AddConfigPath(path)
	viper.SetConfigName("walls-identity-service")
	viper.SetConfigType("env")

	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatal(err)
	}

	var config Configuration
	err = viper.Unmarshal(&config)
	if err != nil {
		log.Fatal(err)
	}

	if config.ExternalConfigPath != "" {
		viper.Reset()
		config = loadConfig(config.ExternalConfigPath)
	}

	return config
}
