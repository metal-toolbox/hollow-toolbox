package ginjwt

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// OIDCConfig provides the configuration for the authentication service
type OIDCConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Audience string `yaml:"audience"`
	Issuer   string `yaml:"issuer"`
	JWKSURI  string `yaml:"jwsuri"`
	Claims   Claims `yaml:"claims"`
}

type Claims struct {
	Roles    string `yaml:"roles"`
	Username string `yaml:"username"`
}

// RegisterViperOIDCFlags ensures that the given Viper and cobra.Command instances
// have the following command line/configuration flags registered:
//
// * `oidc`: Enables/disables OIDC Authentication
//
// A call to this would normally look as follows:
//
//		ginjwt.RegisterViperOIDCFlags(viper.GetViper(), serveCmd)
//
func RegisterViperOIDCFlags(v *viper.Viper, cmd *cobra.Command) {
	cmd.Flags().Bool("oidc", true, "use oidc auth")
	ViperBindFlag("oidc.enabled", cmd.Flags().Lookup("oidc"))
}

// GetAuthConfigFromFlags builds an AuthConfig object from flags provided by
// the viper tooling. This utility function assumes that the
// `RegisterViperOIDCFlags` function was called beforehand.
//
// A call to this would normally look as follows:
//
//		ginjwt.GetAuthConfigFromFlags(viper.GetViper())
//
// Note that when using this function configuration
func GetAuthConfigFromFlags(v *viper.Viper) (AuthConfig, error) {
	var authConfigs []OIDCConfig
	if err := v.UnmarshalKey("oidc", &authConfigs); err != nil {
		// backwards compatible to single entry
		return AuthConfig{}, ErrInvalidAuthConfig
	}

	if len(authConfigs) == 0 {
		return AuthConfig{}, ErrMissingAuthConfig
	}

	config := authConfigs[0]

	if !config.Enabled {
		return AuthConfig{}, nil
	}

	if config.Issuer == "" {
		return AuthConfig{}, ErrMissingIssuerFlag
	}

	if config.JWKSURI == "" {
		return AuthConfig{}, ErrMissingJWKURIFlag
	}

	return AuthConfig{
		Enabled:       config.Enabled,
		Audience:      config.Audience,
		Issuer:        config.Issuer,
		JWKSURI:       config.JWKSURI,
		RolesClaim:    config.Claims.Roles,
		UsernameClaim: config.Claims.Username,
	}, nil
}

// GetAuthConfigsFromFlags builds AuthConfig objects from flags provided by
// the viper tooling. This utility function assumes that the
// `RegisterViperOIDCFlags` function was called beforehand.
//
// A call to this would normally look as follows:
//
//		ginjwt.GetAuthConfigsFromFlags(viper.GetViper())
//
// Note that this function will retrieve as many AuthConfigs as the number
// of issuers and JWK URIs given (which must match)
func GetAuthConfigsFromFlags(v *viper.Viper) ([]AuthConfig, error) {
	var authConfigs []OIDCConfig
	if err := v.UnmarshalKey("oidc", &authConfigs); err != nil {
		return []AuthConfig{}, ErrInvalidAuthConfig
	}

	if len(authConfigs) == 0 {
		return []AuthConfig{}, ErrMissingAuthConfig
	}

	var authcfgs []AuthConfig

	for _, c := range authConfigs {
		if c.Enabled {
			if c.Issuer == "" {
				return []AuthConfig{}, ErrMissingIssuerFlag
			}

			if c.JWKSURI == "" {
				return []AuthConfig{}, ErrMissingJWKURIFlag
			}

			authcfgs = append(authcfgs,
				AuthConfig{
					Enabled:       c.Enabled,
					Audience:      c.Audience,
					Issuer:        c.Issuer,
					JWKSURI:       c.JWKSURI,
					RolesClaim:    c.Claims.Roles,
					UsernameClaim: c.Claims.Username,
				},
			)
		}
	}

	return authcfgs, nil
}

// ViperBindFlag provides a wrapper around the viper bindings that handles error checks
func ViperBindFlag(name string, flag *pflag.Flag) {
	err := viper.BindPFlag(name, flag)
	if err != nil {
		panic(err)
	}
}
