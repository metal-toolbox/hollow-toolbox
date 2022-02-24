package ginjwt

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

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
}

// GetAuthConfigFromFlags builds an AuthConfig object from flags provided by
// the viper tooling. This utility function assumes that the
// `RegisterViperOIDCFlags` function was called beforehand.
//
// A call to this would normally look as follows:
//
//		ginjwt.GetAuthConfigFromFlags(viper.GetViper())
//
// Note that when using this function, this will retrieve the first
// issuer and JWK URI.
func GetAuthConfigFromFlags(v *viper.Viper) (AuthConfig, error) {
	var issuer, jwkuri string

	if !v.GetBool("oidc.enabled") {
		return AuthConfig{}, nil
	}

	givenIssuers := v.GetStringSlice("oidc.issuer")
	givenJWKURIs := v.GetStringSlice("oidc.jwksuri")

	if len(givenIssuers) == 0 {
		return AuthConfig{}, ErrMissingIssuerFlag
	}

	if len(givenJWKURIs) == 0 {
		return AuthConfig{}, ErrMissingJWKURIFlag
	}

	issuer = givenIssuers[0]
	jwkuri = givenJWKURIs[0]

	return AuthConfig{
		Enabled:       v.GetBool("oidc.enabled"),
		Audience:      v.GetString("oidc.audience"),
		Issuer:        issuer,
		JWKSURI:       jwkuri,
		RolesClaim:    v.GetString("oidc.claims.roles"),
		UsernameClaim: v.GetString("oidc.claims.username"),
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
	if !v.GetBool("oidc.enabled") {
		return []AuthConfig{}, nil
	}

	givenIssuers := v.GetStringSlice("oidc.issuer")
	givenJWKURIs := v.GetStringSlice("oidc.jwksuri")

	switch {
	case len(givenIssuers) == 0:
		return nil, ErrMissingIssuerFlag
	case len(givenJWKURIs) == 0:
		return nil, ErrMissingJWKURIFlag
	case len(givenIssuers) != len(givenJWKURIs):
		return nil, ErrIssuersDontMatchJWKURIs
	}

	authcfgs := make([]AuthConfig, len(givenIssuers))
	for idx := range givenIssuers {
		authcfgs[idx] = AuthConfig{
			Enabled:       v.GetBool("oidc.enabled"),
			Audience:      v.GetString("oidc.audience"),
			Issuer:        givenIssuers[idx],
			JWKSURI:       givenJWKURIs[idx],
			RolesClaim:    v.GetString("oidc.claims.roles"),
			UsernameClaim: v.GetString("oidc.claims.username"),
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
