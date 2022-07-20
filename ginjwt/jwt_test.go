package ginjwt_test

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"go.hollow.sh/toolbox/ginauth"
	"go.hollow.sh/toolbox/ginjwt"
)

func TestMiddlewareValidatesTokensWithScopes(t *testing.T) {
	var testCases = []struct {
		testName         string
		middlewareAud    string
		middlewareIss    string
		middlewareScopes []string
		signingKey       *rsa.PrivateKey
		signingKeyID     string
		claims           jwt.Claims
		claimScopes      []string
		responseCode     int
		responseBody     string
	}{
		{
			"unknown keyid",
			"ginjwt.test",
			"ginjwt.test.issuer2",
			[]string{"testScope"},
			ginjwt.TestPrivRSAKey1,
			"randomUnknownID",
			jwt.Claims{
				Subject:   "test-user",
				Issuer:    "ginjwt.test.issuer",
				NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
				Audience:  jwt.Audience{"ginjwt.test", "another.test.service"},
			},
			[]string{"testScope", "anotherScope", "more-scopes"},
			http.StatusUnauthorized,
			"invalid token signing key",
		},
		{
			"incorrect keyid",
			"ginjwt.test",
			"ginjwt.test.issuer2",
			[]string{"testScope"},
			ginjwt.TestPrivRSAKey1,
			ginjwt.TestPrivRSAKey2ID,
			jwt.Claims{
				Subject:   "test-user",
				Issuer:    "ginjwt.test.issuer",
				NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
				Audience:  jwt.Audience{"ginjwt.test", "another.test.service"},
			},
			[]string{"testScope", "anotherScope", "more-scopes"},
			http.StatusUnauthorized,
			"unable to validate auth token",
		},
		{
			"incorrect issuer",
			"ginjwt.test",
			"ginjwt.test.issuer2",
			[]string{"testScope"},
			ginjwt.TestPrivRSAKey1,
			ginjwt.TestPrivRSAKey1ID,
			jwt.Claims{
				Subject:   "test-user",
				Issuer:    "ginjwt.test.issuer",
				NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
				Audience:  jwt.Audience{"ginjwt.test", "another.test.service"},
			},
			[]string{"testScope", "anotherScope", "more-scopes"},
			http.StatusUnauthorized,
			"invalid issuer claim",
		},
		{
			"incorrect audience",
			"ginjwt.testFail",
			"ginjwt.test.issuer",
			[]string{"testScope"},
			ginjwt.TestPrivRSAKey1,
			ginjwt.TestPrivRSAKey1ID,
			jwt.Claims{
				Subject:   "test-user",
				Issuer:    "ginjwt.test.issuer",
				NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
				Audience:  jwt.Audience{"ginjwt.test", "another.test.service"},
			},
			[]string{"testScope", "anotherScope", "more-scopes"},
			http.StatusUnauthorized,
			"invalid audience claim",
		},
		{
			"incorrect scopes",
			"ginjwt.test",
			"ginjwt.test.issuer",
			[]string{"adminscope"},
			ginjwt.TestPrivRSAKey1,
			ginjwt.TestPrivRSAKey1ID,
			jwt.Claims{
				Subject:   "test-user",
				Issuer:    "ginjwt.test.issuer",
				NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
				Audience:  jwt.Audience{"ginjwt.test", "another.test.service"},
			},
			[]string{"testScope", "anotherScope", "more-scopes"},
			http.StatusForbidden,
			"missing required scope",
		},
		{
			"expired token",
			"ginjwt.test",
			"ginjwt.test.issuer",
			[]string{"testScope"},
			ginjwt.TestPrivRSAKey1,
			ginjwt.TestPrivRSAKey1ID,
			jwt.Claims{
				Subject:   "test-user",
				Issuer:    "ginjwt.test.issuer",
				NotBefore: jwt.NewNumericDate(time.Now().Add(-6 * time.Hour)),
				Expiry:    jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
				Audience:  jwt.Audience{"ginjwt.test", "another.test.service"},
			},
			[]string{"testScope", "anotherScope", "more-scopes"},
			http.StatusUnauthorized,
			"token is expired",
		},
		{
			"future token",
			"ginjwt.test",
			"ginjwt.test.issuer",
			[]string{"testScope"},
			ginjwt.TestPrivRSAKey1,
			ginjwt.TestPrivRSAKey1ID,
			jwt.Claims{
				Subject:   "test-user",
				Issuer:    "ginjwt.test.issuer",
				NotBefore: jwt.NewNumericDate(time.Now().Add(6 * time.Hour)),
				Audience:  jwt.Audience{"ginjwt.test", "another.test.service"},
			},
			[]string{"testScope", "anotherScope", "more-scopes"},
			http.StatusUnauthorized,
			"token not valid yet",
		},
		{
			"happy path",
			"ginjwt.test",
			"ginjwt.test.issuer",
			[]string{"testScope"},
			ginjwt.TestPrivRSAKey1,
			ginjwt.TestPrivRSAKey1ID,
			jwt.Claims{
				Subject:   "test-user",
				Issuer:    "ginjwt.test.issuer",
				NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
				Audience:  jwt.Audience{"ginjwt.test", "another.test.service"},
			},
			[]string{"testScope", "anotherScope", "more-scopes"},
			http.StatusOK,
			"ok",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.testName, func(t *testing.T) {
			jwksURI := ginjwt.TestHelperJWKSProvider(ginjwt.TestPrivRSAKey1ID, ginjwt.TestPrivRSAKey2ID)

			cfg := ginjwt.AuthConfig{Enabled: true, Audience: tt.middlewareAud, Issuer: tt.middlewareIss, JWKSURI: jwksURI}
			authMW, err := ginjwt.NewAuthMiddleware(cfg)
			require.NoError(t, err)

			r := gin.New()
			r.Use(authMW.AuthRequired(), authMW.RequiredScopes(tt.middlewareScopes))
			r.GET("/", func(c *gin.Context) {
				c.JSON(http.StatusOK, "ok")
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "http://test/", nil)

			signer := ginjwt.TestHelperMustMakeSigner(jose.RS256, tt.signingKeyID, tt.signingKey)
			rawToken := ginjwt.TestHelperGetToken(signer, tt.claims, "scope", strings.Join(tt.claimScopes, " "))
			req.Header.Set("Authorization", fmt.Sprintf("bearer %s", rawToken))

			r.ServeHTTP(w, req)

			assert.Equal(t, tt.responseCode, w.Code)
			assert.Contains(t, w.Body.String(), tt.responseBody)
		})
	}
}

func TestMiddlewareAuthRequired(t *testing.T) {
	var testCases = []struct {
		testName         string
		middlewareAud    string
		middlewareIss    string
		middlewareScopes []string
		signingKey       *rsa.PrivateKey
		signingKeyID     string
		claims           jwt.Claims
		claimScopes      []string
		responseCode     int
		responseBody     string
	}{
		{
			"unknown keyid",
			"ginjwt.test",
			"ginjwt.test.issuer2",
			[]string{"testScope"},
			ginjwt.TestPrivRSAKey1,
			"randomUnknownID",
			jwt.Claims{
				Subject:   "test-user",
				Issuer:    "ginjwt.test.issuer",
				NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
				Audience:  jwt.Audience{"ginjwt.test", "another.test.service"},
			},
			[]string{"testScope", "anotherScope", "more-scopes"},
			http.StatusUnauthorized,
			"invalid token signing key",
		},
		{
			"incorrect keyid",
			"ginjwt.test",
			"ginjwt.test.issuer2",
			[]string{"testScope"},
			ginjwt.TestPrivRSAKey1,
			ginjwt.TestPrivRSAKey2ID,
			jwt.Claims{
				Subject:   "test-user",
				Issuer:    "ginjwt.test.issuer",
				NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
				Audience:  jwt.Audience{"ginjwt.test", "another.test.service"},
			},
			[]string{"testScope", "anotherScope", "more-scopes"},
			http.StatusUnauthorized,
			"unable to validate auth token",
		},
		{
			"incorrect issuer",
			"ginjwt.test",
			"ginjwt.test.issuer2",
			[]string{"testScope"},
			ginjwt.TestPrivRSAKey1,
			ginjwt.TestPrivRSAKey1ID,
			jwt.Claims{
				Subject:   "test-user",
				Issuer:    "ginjwt.test.issuer",
				NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
				Audience:  jwt.Audience{"ginjwt.test", "another.test.service"},
			},
			[]string{"testScope", "anotherScope", "more-scopes"},
			http.StatusUnauthorized,
			"invalid issuer claim",
		},
		{
			"incorrect audience",
			"ginjwt.testFail",
			"ginjwt.test.issuer",
			[]string{"testScope"},
			ginjwt.TestPrivRSAKey1,
			ginjwt.TestPrivRSAKey1ID,
			jwt.Claims{
				Subject:   "test-user",
				Issuer:    "ginjwt.test.issuer",
				NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
				Audience:  jwt.Audience{"ginjwt.test", "another.test.service"},
			},
			[]string{"testScope", "anotherScope", "more-scopes"},
			http.StatusUnauthorized,
			"invalid audience claim",
		},
		{
			"expired token",
			"ginjwt.test",
			"ginjwt.test.issuer",
			[]string{"testScope"},
			ginjwt.TestPrivRSAKey1,
			ginjwt.TestPrivRSAKey1ID,
			jwt.Claims{
				Subject:   "test-user",
				Issuer:    "ginjwt.test.issuer",
				NotBefore: jwt.NewNumericDate(time.Now().Add(-6 * time.Hour)),
				Expiry:    jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
				Audience:  jwt.Audience{"ginjwt.test", "another.test.service"},
			},
			[]string{"testScope", "anotherScope", "more-scopes"},
			http.StatusUnauthorized,
			"token is expired",
		},
		{
			"future token",
			"ginjwt.test",
			"ginjwt.test.issuer",
			[]string{"testScope"},
			ginjwt.TestPrivRSAKey1,
			ginjwt.TestPrivRSAKey1ID,
			jwt.Claims{
				Subject:   "test-user",
				Issuer:    "ginjwt.test.issuer",
				NotBefore: jwt.NewNumericDate(time.Now().Add(6 * time.Hour)),
				Audience:  jwt.Audience{"ginjwt.test", "another.test.service"},
			},
			[]string{"testScope", "anotherScope", "more-scopes"},
			http.StatusUnauthorized,
			"token not valid yet",
		},
		{
			"happy path",
			"ginjwt.test",
			"ginjwt.test.issuer",
			[]string{"testScope"},
			ginjwt.TestPrivRSAKey1,
			ginjwt.TestPrivRSAKey1ID,
			jwt.Claims{
				Subject:   "test-user",
				Issuer:    "ginjwt.test.issuer",
				NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
				Audience:  jwt.Audience{"ginjwt.test", "another.test.service"},
			},
			[]string{"testScope", "anotherScope", "more-scopes"},
			http.StatusOK,
			"ok",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.testName, func(t *testing.T) {
			jwksURI := ginjwt.TestHelperJWKSProvider(ginjwt.TestPrivRSAKey1ID, ginjwt.TestPrivRSAKey2ID)

			cfg := ginjwt.AuthConfig{Enabled: true, Audience: tt.middlewareAud, Issuer: tt.middlewareIss, JWKSURI: jwksURI}
			authMW, err := ginjwt.NewAuthMiddleware(cfg)
			require.NoError(t, err)

			r := gin.New()
			r.Use(authMW.AuthRequired())
			r.GET("/", func(c *gin.Context) {
				c.JSON(http.StatusOK, "ok")
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "http://test/", nil)

			signer := ginjwt.TestHelperMustMakeSigner(jose.RS256, tt.signingKeyID, tt.signingKey)
			rawToken := ginjwt.TestHelperGetToken(signer, tt.claims, "scope", strings.Join(tt.claimScopes, " "))
			req.Header.Set("Authorization", fmt.Sprintf("bearer %s", rawToken))

			r.ServeHTTP(w, req)

			assert.Equal(t, tt.responseCode, w.Code)
			assert.Contains(t, w.Body.String(), tt.responseBody)
		})
	}
}

func TestInvalidAuthHeader(t *testing.T) {
	var testCases = []struct {
		testName         string
		authHeader       string
		responseCode     int
		responseContains string
	}{
		{
			"no auth header",
			"",
			http.StatusUnauthorized,
			"missing authorization header",
		},
		{
			"wrong format",
			"notbearer token",
			http.StatusUnauthorized,
			"invalid authorization header",
		},
		{
			"invalid token",
			"bearer token",
			http.StatusUnauthorized,
			"unable to parse auth token",
		},
		{
			"token with no kid",
			"bearer eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIiLCJzY29wZXMiOlsiczEiLCJzMiJdLCJzdWIiOiJzdWJqZWN0In0.UDDtyK9gC9kyHltcP7E_XODsnqcJWZIiXeGmSAH7SE9YKy3N0KSfFIN85dCNjTfs6zvy4rkrCHzLB7uKAtzMearh3q7jL4nxbhUMhlUcs_9QDVoN4q_j58XmRqBqRnBk-RmDu9TgcV8RbErP4awpIhwWb5UU-hR__4_iNbHdKqwSUPDKYGlf5eicuiYrPxH8mxivk4LRD-vyRdBZZKBt0XIDnEU4TdcNCzAXojkftqcFWYsczwS8R4JHd1qYsMyiaWl4trdHZkO4QkeLe34z4ZAaPMt3wE-gcU-VoqYTGxz-K3Le2VaZ0r3j_z6bOInsv0yngC_cD1dCXMyQJWnWjQ",
			http.StatusUnauthorized,
			"unable to parse auth token header",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.testName, func(t *testing.T) {
			jwksURI := ginjwt.TestHelperJWKSProvider(ginjwt.TestPrivRSAKey1ID, ginjwt.TestPrivRSAKey2ID)
			cfg := ginjwt.AuthConfig{Enabled: true, Audience: "aud", Issuer: "iss", JWKSURI: jwksURI}
			authMW, err := ginjwt.NewAuthMiddleware(cfg)
			require.NoError(t, err)

			r := gin.New()
			r.Use(authMW.AuthRequired())
			r.GET("/", func(c *gin.Context) {
				c.JSON(http.StatusOK, "ok")
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "http://test/", nil)

			req.Header.Set("Authorization", tt.authHeader)
			r.ServeHTTP(w, req)

			assert.Equal(t, tt.responseCode, w.Code)
			assert.Contains(t, w.Body.String(), tt.responseContains)
		})
	}
}

func TestInvalidJWKURIWithWrongPath(t *testing.T) {
	uri := ginjwt.TestHelperJWKSProvider(ginjwt.TestPrivRSAKey1ID, ginjwt.TestPrivRSAKey2ID)
	uri += "/some-extra-path"
	cfg := ginjwt.AuthConfig{Enabled: true, Audience: "aud", Issuer: "iss", JWKSURI: uri}
	_, err := ginjwt.NewAuthMiddleware(cfg)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ginauth.ErrMiddlewareRemote)
}

func TestVerifyTokenWithScopes(t *testing.T) {
	var testCases = []struct {
		testName         string
		middlewareAud    string
		middlewareIss    string
		middlewareScopes []string
		signingKey       *rsa.PrivateKey
		signingKeyID     string
		claims           jwt.Claims
		claimScopes      []string
		wantScopes       []string
		want             ginauth.ClaimMetadata
		wantErr          bool
	}{
		{
			testName:         "missing all scopes",
			middlewareAud:    "ginjwt.test",
			middlewareIss:    "ginjwt.test.issuer",
			middlewareScopes: []string{"adminscope"},
			signingKey:       ginjwt.TestPrivRSAKey1,
			signingKeyID:     ginjwt.TestPrivRSAKey1ID,
			claims: jwt.Claims{
				Subject:   "test-user",
				Issuer:    "ginjwt.test.issuer",
				NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
				Audience:  jwt.Audience{"ginjwt.test", "another.test.service"},
			},
			claimScopes: []string{"testScope", "anotherScope", "more-scopes"},
			wantScopes:  []string{"admin-scopes"},
			want:        ginauth.ClaimMetadata{},
			wantErr:     true,
		},
		{
			testName:         "missing some scopes",
			middlewareAud:    "ginjwt.test",
			middlewareIss:    "ginjwt.test.issuer",
			middlewareScopes: []string{"adminscope"},
			signingKey:       ginjwt.TestPrivRSAKey1,
			signingKeyID:     ginjwt.TestPrivRSAKey1ID,
			claims: jwt.Claims{
				Subject:   "test-user",
				Issuer:    "ginjwt.test.issuer",
				NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
				Audience:  jwt.Audience{"ginjwt.test", "another.test.service"},
			},
			claimScopes: []string{"testScope"},
			wantScopes:  []string{"testScope", "anotherScope"},
			want:        ginauth.ClaimMetadata{},
			wantErr:     true,
		},
		{
			testName:         "no wanted scopes",
			middlewareAud:    "ginjwt.test",
			middlewareIss:    "ginjwt.test.issuer",
			middlewareScopes: []string{"adminscope"},
			signingKey:       ginjwt.TestPrivRSAKey1,
			signingKeyID:     ginjwt.TestPrivRSAKey1ID,
			claims: jwt.Claims{
				Subject:   "test-user",
				Issuer:    "ginjwt.test.issuer",
				NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
				Audience:  jwt.Audience{"ginjwt.test", "another.test.service"},
			},
			claimScopes: []string{"admin-scopes"},
			wantScopes:  []string{},
			want: ginauth.ClaimMetadata{
				Subject: "test-user",
				User:    "test-user",
				Roles: []string{
					"admin-scopes",
				},
			},
			wantErr: false,
		},
		{
			testName:         "happy path",
			middlewareAud:    "ginjwt.test",
			middlewareIss:    "ginjwt.test.issuer",
			middlewareScopes: []string{"testScope"},
			signingKey:       ginjwt.TestPrivRSAKey1,
			signingKeyID:     ginjwt.TestPrivRSAKey1ID,
			claims: jwt.Claims{
				Subject:   "test-user",
				Issuer:    "ginjwt.test.issuer",
				NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
				Audience:  jwt.Audience{"ginjwt.test", "another.test.service"},
			},
			claimScopes: []string{"testScope", "anotherScope", "more-scopes"},
			wantScopes:  []string{"testScope", "anotherScope", "more-scopes"},
			want: ginauth.ClaimMetadata{
				Subject: "test-user",
				User:    "test-user",
				Roles: []string{
					"testScope",
					"anotherScope",
					"more-scopes",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.testName, func(t *testing.T) {
			jwksURI := ginjwt.TestHelperJWKSProvider(ginjwt.TestPrivRSAKey1ID, ginjwt.TestPrivRSAKey2ID)
			config := ginjwt.AuthConfig{
				Enabled:  true,
				Audience: tt.middlewareAud,
				Issuer:   tt.middlewareIss,
				JWKSURI:  jwksURI,
			}
			m, err := ginjwt.NewAuthMiddleware(config)
			assert.NoError(t, err)

			ctx := &gin.Context{}
			signer := ginjwt.TestHelperMustMakeSigner(jose.RS256, tt.signingKeyID, tt.signingKey)
			rawToken := ginjwt.TestHelperGetToken(signer, tt.claims, "scope", strings.Join(tt.claimScopes, " "))

			// dummy http request
			req, _ := http.NewRequest(http.MethodGet, "http://foo.bar", bytes.NewReader([]byte{}))
			ctx.Request = req
			ctx.Request.Header.Set("Authorization", fmt.Sprintf("bearer %s", rawToken))

			got, err := m.VerifyTokenWithScopes(ctx, tt.wantScopes)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
