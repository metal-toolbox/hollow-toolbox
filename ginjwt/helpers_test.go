package ginjwt_test

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"go.hollow.sh/toolbox/ginjwt"
)

func TestRegisterViperOIDCFlags(t *testing.T) {
	tests := []struct {
		name               string
		expectedAuthConfig ginjwt.AuthConfig
		wantErr            bool
	}{
		{
			name: "Get AuthConfig from parameters scenario 1",
			expectedAuthConfig: ginjwt.AuthConfig{
				Enabled:       true,
				Audience:      "tacos",
				Issuer:        "are",
				JWKSURI:       "https://bit.ly/3HlVmWp",
				RolesClaim:    "pretty",
				UsernameClaim: "awesome",
			},
		},
		{
			name: "Get AuthConfig from parameters scenario 2",
			expectedAuthConfig: ginjwt.AuthConfig{
				Enabled:       true,
				Audience:      "beer",
				Issuer:        "is",
				JWKSURI:       "https://bit.ly/3HlVmWp",
				RolesClaim:    "quite",
				UsernameClaim: "tasty",
			},
		},
		{
			name: "Get AuthConfig fails due to missing issuer",
			expectedAuthConfig: ginjwt.AuthConfig{
				Enabled:       true,
				Audience:      "beer",
				Issuer:        "",
				JWKSURI:       "https://bit.ly/3HlVmWp",
				RolesClaim:    "quite",
				UsernameClaim: "tasty",
			},
			wantErr: true,
		},

		{
			name: "Get AuthConfig fails due to missing JWK URI",
			expectedAuthConfig: ginjwt.AuthConfig{
				Enabled:       true,
				Audience:      "beer",
				Issuer:        "is",
				JWKSURI:       "",
				RolesClaim:    "quite",
				UsernameClaim: "tasty",
			},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := viper.New()
			cmd := &cobra.Command{}

			ginjwt.RegisterViperOIDCFlags(v, cmd)

			v.Set("oidc.enabled", tc.expectedAuthConfig.Enabled)
			v.Set("oidc.audience", tc.expectedAuthConfig.Audience)
			if tc.expectedAuthConfig.Issuer != "" {
				v.Set("oidc.issuer", []string{tc.expectedAuthConfig.Issuer})
			}
			if tc.expectedAuthConfig.JWKSURI != "" {
				v.Set("oidc.jwksuri", []string{tc.expectedAuthConfig.JWKSURI})
			}
			v.Set("oidc.claims.roles", tc.expectedAuthConfig.RolesClaim)
			v.Set("oidc.claims.username", tc.expectedAuthConfig.UsernameClaim)

			gotAT, err := ginjwt.GetAuthConfigFromFlags(v)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				assert.Equal(t, tc.expectedAuthConfig.Enabled, gotAT.Enabled)
				assert.Equal(t, tc.expectedAuthConfig.Audience, gotAT.Audience)
				assert.Equal(t, tc.expectedAuthConfig.Issuer, gotAT.Issuer)
				assert.Equal(t, tc.expectedAuthConfig.JWKSURI, gotAT.JWKSURI)
				assert.Equal(t, tc.expectedAuthConfig.RolesClaim, gotAT.RolesClaim)
				assert.Equal(t, tc.expectedAuthConfig.UsernameClaim, gotAT.UsernameClaim)
			}
		})
	}
}

func TestRegisterViperOIDCFlagsForMultipleConfigs(t *testing.T) {
	type Args struct {
		Enabled       bool
		Audience      string
		Issuer        []string
		JWKSURI       []string
		RolesClaim    string
		UsernameClaim string
	}

	tests := []struct {
		name                string
		args                Args
		expectedAuthConfigs []ginjwt.AuthConfig
		wantErr             bool
	}{
		{
			name: "Get AuthConfig from parameters with one issuer and JWK URI",
			args: Args{
				Enabled:       true,
				Audience:      "tacos",
				Issuer:        []string{"are"},
				JWKSURI:       []string{"https://bit.ly/3HlVmWp"},
				RolesClaim:    "pretty",
				UsernameClaim: "awesome",
			},
			expectedAuthConfigs: []ginjwt.AuthConfig{
				{
					Enabled:       true,
					Audience:      "tacos",
					Issuer:        "are",
					JWKSURI:       "https://bit.ly/3HlVmWp",
					RolesClaim:    "pretty",
					UsernameClaim: "awesome",
				},
			},
		},
		{
			name: "Get AuthConfig from parameters with two issuers and JWK URIs",
			args: Args{
				Enabled:  true,
				Audience: "Hey Jude",
				Issuer:   []string{"don't make it bad", "don't be afraid"},
				JWKSURI: []string{
					"take a sad song and make it better",
					"You were made to go out and get her",
				},
				RolesClaim:    "Na na na nananana",
				UsernameClaim: "nannana, hey Jude...",
			},
			expectedAuthConfigs: []ginjwt.AuthConfig{
				{
					Enabled:       true,
					Audience:      "Hey Jude",
					Issuer:        "don't make it bad",
					JWKSURI:       "take a sad song and make it better",
					RolesClaim:    "Na na na nananana",
					UsernameClaim: "nannana, hey Jude...",
				},
				{
					Enabled:       true,
					Audience:      "Hey Jude",
					Issuer:        "don't be afraid",
					JWKSURI:       "You were made to go out and get her",
					RolesClaim:    "Na na na nananana",
					UsernameClaim: "nannana, hey Jude...",
				},
			},
		},
		{
			name: "Get AuthConfig fails due to missing issuer",
			args: Args{
				Enabled:       true,
				Audience:      "beer",
				Issuer:        []string{},
				JWKSURI:       []string{"https://bit.ly/3HlVmWp"},
				RolesClaim:    "quite",
				UsernameClaim: "tasty",
			},
			wantErr: true,
		},
		{
			name: "Get AuthConfig fails due to missing JWK URI",
			args: Args{
				Enabled:       true,
				Audience:      "beer",
				Issuer:        []string{"is"},
				JWKSURI:       nil,
				RolesClaim:    "quite",
				UsernameClaim: "tasty",
			},
			wantErr: true,
		},
		{
			name: "Get AuthConfig fails due to missing number of issuers not matching number of JWK URIs",
			args: Args{
				Enabled:       true,
				Audience:      "nana",
				Issuer:        []string{"nana", "nana", "nana"},
				JWKSURI:       []string{"nana"},
				RolesClaim:    "nana na...",
				UsernameClaim: "BATMAN!",
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := viper.New()
			cmd := &cobra.Command{}

			ginjwt.RegisterViperOIDCFlags(v, cmd)

			v.Set("oidc.enabled", tc.args.Enabled)
			v.Set("oidc.audience", tc.args.Audience)
			v.Set("oidc.issuer", tc.args.Issuer)
			v.Set("oidc.jwksuri", tc.args.JWKSURI)
			v.Set("oidc.claims.roles", tc.args.RolesClaim)
			v.Set("oidc.claims.username", tc.args.UsernameClaim)

			gotATs, err := ginjwt.GetAuthConfigsFromFlags(v)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)

			for idx, gotAT := range gotATs {
				assert.Equal(t, tc.args.Enabled, gotAT.Enabled)
				assert.Equal(t, tc.args.Audience, gotAT.Audience)
				assert.Equal(t, tc.args.Issuer[idx], gotAT.Issuer)
				assert.Equal(t, tc.args.JWKSURI[idx], gotAT.JWKSURI)
				assert.Equal(t, tc.args.RolesClaim, gotAT.RolesClaim)
				assert.Equal(t, tc.args.UsernameClaim, gotAT.UsernameClaim)
			}
		})
	}
}
