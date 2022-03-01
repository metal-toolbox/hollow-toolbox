package ginjwt_test

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"go.hollow.sh/toolbox/ginjwt"
)

func TestRegisterViperOIDCFlagsSingleProvider(t *testing.T) {
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
			v.Set("oidc.issuer", tc.expectedAuthConfig.Issuer)
			v.Set("oidc.jwksuri", tc.expectedAuthConfig.JWKSURI)
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

func TestRegisterViperOIDCFlags(t *testing.T) {
	tests := []struct {
		name               string
		config             []ginjwt.OIDCConfig
		expectedAuthConfig []ginjwt.AuthConfig
		wantErr            bool
	}{
		{
			name: "Get AuthConfig from parameters scenario 1",
			config: []ginjwt.OIDCConfig{
				{
					Enabled:  true,
					Audience: "tacos",
					Issuer:   "are",
					JWKSURI:  "https://bit.ly/3HlVmWp",
					Claims: ginjwt.Claims{
						Roles:    "pretty",
						Username: "awesome",
					},
				},
			},
			expectedAuthConfig: []ginjwt.AuthConfig{
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
			name: "Get AuthConfig from parameters scenario 2",
			config: []ginjwt.OIDCConfig{
				{
					Enabled:  true,
					Audience: "beer",
					Issuer:   "is",
					JWKSURI:  "https://bit.ly/3HlVmWp",
					Claims: ginjwt.Claims{
						Roles:    "quite",
						Username: "tasty",
					},
				},
			},
			expectedAuthConfig: []ginjwt.AuthConfig{
				{
					Enabled:       true,
					Audience:      "beer",
					Issuer:        "is",
					JWKSURI:       "https://bit.ly/3HlVmWp",
					RolesClaim:    "quite",
					UsernameClaim: "tasty",
				},
			},
		},
		{
			name: "Get AuthConfig from parameters only return first",
			config: []ginjwt.OIDCConfig{
				{
					Enabled:  true,
					Audience: "beer",
					Issuer:   "is",
					JWKSURI:  "https://bit.ly/3HlVmWp",
					Claims: ginjwt.Claims{
						Roles:    "quite",
						Username: "tasty",
					},
				},
				{
					Enabled:  true,
					Audience: "beer",
					Issuer:   "isnt",
					JWKSURI:  "https://bit.ly/3HlVmAc",
					Claims: ginjwt.Claims{
						Roles:    "that",
						Username: "tasty",
					},
				},
			},
			expectedAuthConfig: []ginjwt.AuthConfig{
				{
					Enabled:       true,
					Audience:      "beer",
					Issuer:        "is",
					JWKSURI:       "https://bit.ly/3HlVmWp",
					RolesClaim:    "quite",
					UsernameClaim: "tasty",
				},
			},
		},
		{
			name: "Get AuthConfig fails due to missing issuer",
			config: []ginjwt.OIDCConfig{
				{
					Enabled:  true,
					Audience: "beer",
					Issuer:   "",
					JWKSURI:  "https://bit.ly/3HlVmWp",
					Claims: ginjwt.Claims{
						Roles:    "quite",
						Username: "tasty",
					},
				},
			},
			expectedAuthConfig: []ginjwt.AuthConfig{
				{
					Enabled:       true,
					Audience:      "beer",
					Issuer:        "",
					JWKSURI:       "https://bit.ly/3HlVmWp",
					RolesClaim:    "quite",
					UsernameClaim: "tasty",
				},
			},
			wantErr: true,
		},

		{
			name: "Get AuthConfig fails due to missing JWK URI",
			config: []ginjwt.OIDCConfig{
				{
					Enabled:  true,
					Audience: "beer",
					Issuer:   "is",
					JWKSURI:  "",
					Claims: ginjwt.Claims{
						Roles:    "quite",
						Username: "tasty",
					},
				},
			},
			expectedAuthConfig: []ginjwt.AuthConfig{
				{
					Enabled:       true,
					Audience:      "beer",
					Issuer:        "is",
					JWKSURI:       "",
					RolesClaim:    "quite",
					UsernameClaim: "tasty",
				},
			},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := viper.New()
			cmd := &cobra.Command{}

			ginjwt.RegisterViperOIDCFlags(v, cmd)

			v.Set("oidc", tc.config)

			gotAT, err := ginjwt.GetAuthConfigFromFlags(v)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				assert.Equal(t, tc.expectedAuthConfig[0].Enabled, gotAT.Enabled)
				assert.Equal(t, tc.expectedAuthConfig[0].Audience, gotAT.Audience)
				assert.Equal(t, tc.expectedAuthConfig[0].Issuer, gotAT.Issuer)
				assert.Equal(t, tc.expectedAuthConfig[0].JWKSURI, gotAT.JWKSURI)
				assert.Equal(t, tc.expectedAuthConfig[0].RolesClaim, gotAT.RolesClaim)
				assert.Equal(t, tc.expectedAuthConfig[0].UsernameClaim, gotAT.UsernameClaim)
			}
		})
	}
}

func TestRegisterViperOIDCFlagsForMultipleConfigs(t *testing.T) {
	tests := []struct {
		name                string
		config              []ginjwt.OIDCConfig
		expectedAuthConfigs []ginjwt.AuthConfig
		wantErr             bool
	}{
		{
			name: "Get AuthConfig from parameters with one issuer and JWK URI",
			config: []ginjwt.OIDCConfig{
				{
					Enabled:  true,
					Audience: "tacos",
					Issuer:   "are",
					JWKSURI:  "https://bit.ly/3HlVmWp",
					Claims: ginjwt.Claims{
						Roles:    "pretty",
						Username: "awesome",
					},
				},
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
			name: "Get AuthConfig from parameters with two valid configs",
			config: []ginjwt.OIDCConfig{
				{
					Enabled:  true,
					Audience: "Hey Jude",
					Issuer:   "don't make it bad",
					JWKSURI:  "take a sad song and make it better",
					Claims: ginjwt.Claims{
						Roles:    "Na na na nananana",
						Username: "nannana, hey Jude...",
					},
				},
				{
					Enabled:  true,
					Audience: "Hey Jude",
					Issuer:   "don't be afraid",
					JWKSURI:  "You were made to go out and get her",
					Claims: ginjwt.Claims{
						Roles:    "Na na na nananana",
						Username: "nannana, hey Jude...",
					},
				},
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
			config: []ginjwt.OIDCConfig{
				{
					Enabled:  true,
					Audience: "beer",
					Issuer:   "",
					JWKSURI:  "https://bit.ly/3HlVmWp",
					Claims: ginjwt.Claims{
						Roles:    "quite",
						Username: "tasty",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Get AuthConfig fails due to missing JWK URI",
			config: []ginjwt.OIDCConfig{
				{
					Enabled:  true,
					Audience: "beer",
					Issuer:   "is",
					JWKSURI:  "",
					Claims: ginjwt.Claims{
						Roles:    "quite",
						Username: "tasty",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Get no AuthConfigs if OIDC is diabled",
			config: []ginjwt.OIDCConfig{
				{
					Enabled:  false,
					Audience: "",
					Issuer:   "",
					JWKSURI:  "",
					Claims: ginjwt.Claims{
						Roles:    "",
						Username: "",
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := viper.New()
			cmd := &cobra.Command{}

			ginjwt.RegisterViperOIDCFlags(v, cmd)

			v.Set("oidc", tc.config)

			gotACs, err := ginjwt.GetAuthConfigsFromFlags(v)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)

			for idx, ac := range gotACs {
				assert.Equal(t, tc.config[idx].Enabled, ac.Enabled)
				assert.Equal(t, tc.config[idx].Audience, ac.Audience)
				assert.Equal(t, tc.config[idx].Issuer, ac.Issuer)
				assert.Equal(t, tc.config[idx].JWKSURI, ac.JWKSURI)
				assert.Equal(t, tc.config[idx].Claims.Roles, ac.RolesClaim)
				assert.Equal(t, tc.config[idx].Claims.Username, ac.UsernameClaim)
			}
		})
	}
}
