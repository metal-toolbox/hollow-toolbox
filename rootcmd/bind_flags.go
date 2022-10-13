package rootcmd

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// ViperBindFlag provides a wrapper around the viper bindings that handles error checks
func ViperBindFlag(name string, flag *pflag.Flag) {
	err := viper.BindPFlag(name, flag)
	if err != nil {
		panic(err)
	}
}
