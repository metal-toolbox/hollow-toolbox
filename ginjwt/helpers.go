package ginjwt

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// OIDCConfig provides the configuration for the authentication service
type OIDCConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Audience      string `yaml:"audience"`
	Issuer        string `yaml:"issuer"`
	JWKSURI       string `yaml:"jwsuri"`
	RolesClaim    string `yaml:"claims.roles"`
	UsernameClaim string `yaml:"claims.user"`
}

// RegisterViperOIDCFlags ensures that the given Viper and cobra.Command instances
// have the following command line/configuration flags registered:
//
// * `oidc`: Enables/disables OIDC Authentication
// * `oidc-aud`: Specifies the expected audience for the JWT token
// * `oidc-issuer`: Specifies the expected issuer for the JWT token (can be more than one value)
// * `oidc-jwksuri`: Specifies the JSON Web Key Set (JWKS) URI (can be more than one value).
// * `oidc-roles-claim`: Specifies the roles to be accepted for the JWT claim.
// * `oidc-username-claim`: Specifies a username to use for the JWT claim
//
// A call to this would normally look as follows:
//
//		ginjwt.RegisterViperOIDCFlags(viper.GetViper(), serveCmd)
//
// Note that when specifying multiple issuers and JWK URIs, the amounts must match (e.g.
// there must be as many issuers as there are JWK URIs). The order of how these are specified matters
// too, the first issuer will match the first JWK URI when building an AuthConfig.
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
	oidc := v.Get("oidc")

	authConfig, ok := oidc.([]OIDCConfig)
	if !ok {
		return AuthConfig{}, ErrInvalidAuthConfig
	}

	if len(authConfig) == 0 {
		return AuthConfig{}, ErrMissingAuthConfig
	}

	config := authConfig[0]

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
		RolesClaim:    config.RolesClaim,
		UsernameClaim: config.UsernameClaim,
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
	oidc := v.Get("oidc")

	authConfigs, ok := oidc.([]OIDCConfig)
	if !ok {
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
					RolesClaim:    c.RolesClaim,
					UsernameClaim: c.UsernameClaim,
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
