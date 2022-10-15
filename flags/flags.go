// Package flags contains functions shared
package flags

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// MustBindPFlag binds a viper name to a spf13/pflag and panics on error
func MustBindPFlag(name string, flag *pflag.Flag) {
	err := viper.BindPFlag(name, flag)
	if err != nil {
		panic(err)
	}
}
