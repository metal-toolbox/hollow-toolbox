package flags

import "github.com/spf13/cobra"

// SetFlagsOIDC provides the flags common to OIDC configuration
func SetFlagsOIDC(cmd *cobra.Command) {
	cmd.Flags().Bool("oidc", true, "use oidc auth")
	ViperBindFlag("oidc.enabled", cmd.Flags().Lookup("oidc"))

	cmd.Flags().String("oidc-aud", "", "expected audient on OIDC JWT")
	ViperBindFlag("oidc.audience", cmd.Flags().Lookup("oidc-aud"))

	cmd.Flags().String("oidc-issuer", "", "expected issuer of OIDC JWT")
	ViperBindFlag("oidc.issuer", cmd.Flags().Lookup("oidc-issuer"))

	cmd.Flags().String("oidc-jwksuri", "", "URI for JWKS listing for JWTs")
	ViperBindFlag("oidc.jwksuri", cmd.Flags().Lookup("oidc-jwksuri"))

	cmd.Flags().String("oidc-roles-claim", "claim", "field containing the permissions of an OIDC JWT")
	ViperBindFlag("oidc.claims.roles", cmd.Flags().Lookup("oidc-roles-claim"))

	cmd.Flags().String("oidc-username-claim", "", "additional fields to output in logs from the JWT token, ex (email)")
	ViperBindFlag("oidc.claims.username", cmd.Flags().Lookup("oidc-username-claim"))
}
