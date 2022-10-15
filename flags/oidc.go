package flags

import "github.com/spf13/cobra"

// SetFlagsOIDC provides the flags common to OIDC configuration
//
//	Settings for OIDC:
//	    oidc.enabled			--oidc  (default: true)
//	    oidc.audience			--oidc-aud <string>
//	    oidc.issuer				--oidc-issuer <string>
//	    oidc.jwksuri			--oidc-jwksuri <string>
//	    oidc.claims.roles		--oidc-roles-claims <string(,string,...)>
//	    oidc.claims.username	--oidc-username-claims <string>
func SetFlagsOIDC(cmd *cobra.Command) {
	cmd.Flags().Bool("oidc", true, "use oidc auth")
	MustBindPFlag("oidc.enabled", cmd.Flags().Lookup("oidc"))

	cmd.Flags().String("oidc-aud", "", "expected audient on OIDC JWT")
	MustBindPFlag("oidc.audience", cmd.Flags().Lookup("oidc-aud"))

	cmd.Flags().String("oidc-issuer", "", "expected issuer of OIDC JWT")
	MustBindPFlag("oidc.issuer", cmd.Flags().Lookup("oidc-issuer"))

	cmd.Flags().String("oidc-jwksuri", "", "URI for JWKS listing for JWTs")
	MustBindPFlag("oidc.jwksuri", cmd.Flags().Lookup("oidc-jwksuri"))

	cmd.Flags().String("oidc-roles-claim", "claim", "field containing the permissions of an OIDC JWT")
	MustBindPFlag("oidc.claims.roles", cmd.Flags().Lookup("oidc-roles-claim"))

	cmd.Flags().String("oidc-username-claim", "", "additional fields to output in logs from the JWT token, ex (email)")
	MustBindPFlag("oidc.claims.username", cmd.Flags().Lookup("oidc-username-claim"))
}
