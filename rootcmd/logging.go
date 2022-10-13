package rootcmd

import (
	"go.hollow.sh/toolbox/version"

	"go.uber.org/zap"
)

// SetupLogging is a common configuraion of a zap.SugaredLogger, set to the logger passed
func SetupLogging(app string, pretty, debug bool, logger *zap.SugaredLogger) {
	defer logger.Sync() //nolint:errcheck

	cfg := zap.NewProductionConfig()
	if pretty {
		cfg = zap.NewDevelopmentConfig()
	}

	if debug {
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	} else {
		cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	l, err := cfg.Build()
	if err != nil {
		panic(err)
	}

	logger = l.Sugar().With("app", app, "version", version.Version()) //nolint:staticcheck
}
