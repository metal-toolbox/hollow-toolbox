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

			v.Set("oidc", tc.expectedAuthConfig)

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
		expectedAuthConfig []ginjwt.AuthConfig
		wantErr            bool
	}{
		{
			name: "Get AuthConfig from parameters scenario 1",
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

			v.Set("oidc", tc.expectedAuthConfig)

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
		config              []ginjwt.AuthConfig
		expectedAuthConfigs []ginjwt.AuthConfig
		wantErr             bool
	}{
		{
			name: "Get AuthConfig from parameters with one issuer and JWK URI",
			config: []ginjwt.AuthConfig{
				{
					Enabled:       true,
					Audience:      "tacos",
					Issuer:        "are",
					JWKSURI:       "https://bit.ly/3HlVmWp",
					RolesClaim:    "pretty",
					UsernameClaim: "awesome",
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
			config: []ginjwt.AuthConfig{
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
			config: []ginjwt.AuthConfig{
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
			config: []ginjwt.AuthConfig{
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
		{
			name: "Get no AuthConfigs if OIDC is diabled",
			config: []ginjwt.AuthConfig{
				{
					Enabled:       false,
					Audience:      "",
					Issuer:        "",
					JWKSURI:       "",
					RolesClaim:    "",
					UsernameClaim: "",
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
				assert.Equal(t, tc.config[idx].RolesClaim, ac.RolesClaim)
				assert.Equal(t, tc.config[idx].UsernameClaim, ac.UsernameClaim)
			}
		})
	}
}
