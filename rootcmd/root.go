package rootcmd

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"go.hollow.sh/toolbox/flags"
)

var alphaRegex *regexp.Regexp

// Root contains a cobra.Command and options
type Root struct {
	Cmd     *cobra.Command
	Options *Options
}

func init() {
	alphaRegex = regexp.MustCompile("^[a-z]+$")
}

// NewRootCmd returns a
func NewRootCmd(app, short string) *Root {
	app = strings.ToLower(app)
	if !alphaRegex.MatchString(app) {
		fmt.Println("app name: " + app)

		panic("app name must only contain alpha characters")
	}

	return &Root{
		Cmd: &cobra.Command{
			Use:   app,
			Short: short,
		},
		Options: &Options{
			App: app,
		},
	}
}

// InitFlags are the 3 common flags for rootcmd
func (r *Root) InitFlags() {
	r.Cmd.PersistentFlags().StringVar(&r.Options.ConfigFile, "config", "", "config file (default is $HOME/."+r.Options.App+".yaml)")

	r.Cmd.PersistentFlags().BoolVar(&r.Options.Debug, "debug", false, "enable debug logging")
	flags.MustBindPFlag("logging.debug", r.Cmd.PersistentFlags().Lookup("debug"))

	r.Cmd.PersistentFlags().BoolVar(&r.Options.PrettyPrint, "pretty", false, "enable pretty (human readable) logging output")
	flags.MustBindPFlag("logging.pretty", r.Cmd.PersistentFlags().Lookup("pretty"))
}

// Execute is a vanity wrapper on cobra.Command.Execute()
func (r *Root) Execute() error {
	return r.Cmd.Execute()
}
