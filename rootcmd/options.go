package rootcmd

import (
	"strings"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"go.hollow.sh/toolbox/version"

	"go.uber.org/zap"
)

// Options are the basic setting rootcmd needs or sets
type Options struct {
	App         string
	ConfigFile  string
	Debug       bool
	PrettyPrint bool
	logger      *zap.SugaredLogger
}

// GetLogger returns the zap.SugarLogger
func (o *Options) GetLogger() *zap.SugaredLogger {
	return o.logger
}

// GetConfigFile returns the path to the config file
func (o *Options) GetConfigFile() string {
	return o.ConfigFile
}

// SetupLogging is a common configuraion of a zap.SugaredLogger, set to the logger passed
func (o *Options) SetupLogging(logger *zap.SugaredLogger) {
	defer logger.Sync() //nolint:errcheck

	cfg := zap.NewProductionConfig()
	if o.PrettyPrint {
		cfg = zap.NewDevelopmentConfig()
	}

	if o.Debug {
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	} else {
		cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	l, err := cfg.Build()
	if err != nil {
		panic(err)
	}

	logger = l.Sugar().With("app", o.App, "version", version.Version())
	o.logger = logger
}

// InitConfig reads in config file and ENV variables if set.
func (o *Options) InitConfig() {
	if o.ConfigFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(o.ConfigFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".hollow" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName("." + o.App)
	}

	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.SetEnvPrefix(o.App)
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	err := viper.ReadInConfig()

	if err == nil {
		o.logger.Infow("using config file",
			"file", viper.ConfigFileUsed(),
		)
	}
}
