package ginjwt

import (
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// OIDCConfig provides the configuration for the oidc provider auth configuration
type OIDCConfig struct {
	Enabled           bool          `yaml:"enabled"`
	Audience          string        `yaml:"audience"`
	Issuer            string        `yaml:"issuer"`
	JWKSURI           string        `yaml:"jwsuri"`
	JWKSRemoteTimeout time.Duration `yaml:"jwksremotetimeout"`
	Claims            Claims        `yaml:"claims"`
}

// Claims defines the roles and username claims for the given oidc provider
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
// The oidc configuration should be passed in through a yaml file due to the nested
// structure of the fields, however, if only one oidc provider is used the flag parameters would work
//
// * `oidc-aud`: Specifies the expected audience for the JWT token
// * `oidc-issuer`: Specifies the expected issuer for the JWT token (can be more than one value)
// * `oidc-jwksuri`: Specifies the JSON Web Key Set (JWKS) URI (can be more than one value).
// * `oidc-roles-claim`: Specifies the roles to be accepted for the JWT claim.
// * `oidc-username-claim`: Specifies a username to use for the JWT claim
// * `oidc-jwks-remotetimeout`: Specifies a timeout for the JWKS URI
//
func RegisterViperOIDCFlags(v *viper.Viper, cmd *cobra.Command) {
	cmd.Flags().Bool("oidc", true, "use oidc auth")
	ViperBindFlag("oidc.enabled", cmd.Flags().Lookup("oidc"))
	cmd.Flags().String("oidc-aud", "", "expected audience on OIDC JWT")
	ViperBindFlag("oidc.audience", cmd.Flags().Lookup("oidc-aud"))
	cmd.Flags().StringSlice("oidc-issuer", []string{}, "expected issuer of OIDC JWT")
	ViperBindFlag("oidc.issuer", cmd.Flags().Lookup("oidc-issuer"))
	cmd.Flags().StringSlice("oidc-jwksuri", []string{}, "URI for JWKS listing for JWTs")
	ViperBindFlag("oidc.jwksuri", cmd.Flags().Lookup("oidc-jwksuri"))
	cmd.Flags().String("oidc-roles-claim", "claim", "field containing the permissions of an OIDC JWT")
	ViperBindFlag("oidc.claims.roles", cmd.Flags().Lookup("oidc-roles-claim"))
	cmd.Flags().String("oidc-username-claim", "", "additional fields to output in logs from the JWT token, ex (email)")
	ViperBindFlag("oidc.claims.username", cmd.Flags().Lookup("oidc-username-claim"))
	cmd.Flags().Duration("oidc-jwks-remote-timeout", 1*time.Minute, "timeout for remote JWKS fetching")
	ViperBindFlag("oidc.jwksremotetimeout", cmd.Flags().Lookup("oidc-jwks-remote-timeout"))
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
		Enabled:           config.Enabled,
		Audience:          config.Audience,
		Issuer:            config.Issuer,
		JWKSURI:           config.JWKSURI,
		JWKSRemoteTimeout: config.JWKSRemoteTimeout,
		RolesClaim:        config.Claims.Roles,
		UsernameClaim:     config.Claims.Username,
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
					Enabled:           c.Enabled,
					Audience:          c.Audience,
					Issuer:            c.Issuer,
					JWKSURI:           c.JWKSURI,
					JWKSRemoteTimeout: c.JWKSRemoteTimeout,
					RolesClaim:        c.Claims.Roles,
					UsernameClaim:     c.Claims.Username,
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
