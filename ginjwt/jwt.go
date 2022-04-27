package ginjwt

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"go.hollow.sh/toolbox/ginauth"
)

const (
	contextKeySubject       = "jwt.subject"
	contextKeyUser          = "jwt.user"
	contextKeyRoles         = "jwt.roles"
	expectedAuthHeaderParts = 2
)

// Middleware provides a gin compatible middleware that will authenticate JWT requests
type Middleware struct {
	config     AuthConfig
	cachedJWKS jose.JSONWebKeySet
}

// AuthConfig provides the configuration for the authentication service
type AuthConfig struct {
	Enabled       bool
	Audience      string
	Issuer        string
	JWKSURI       string
	LogFields     []string
	RolesClaim    string
	UsernameClaim string
}

// NewAuthMiddleware will return an auth middleware configured with the jwt parameters passed in
func NewAuthMiddleware(cfg AuthConfig) (*Middleware, error) {
	if cfg.RolesClaim == "" {
		cfg.RolesClaim = "scope"
	}

	if cfg.UsernameClaim == "" {
		cfg.UsernameClaim = "sub"
	}

	mw := &Middleware{
		config: cfg,
	}

	if !cfg.Enabled {
		return mw, nil
	}

	if err := mw.refreshJWKS(); err != nil {
		return nil, err
	}

	return mw, nil
}

// SetMetadata sets the needed metadata to the gin context which came from the token
func (m *Middleware) SetMetadata(c *gin.Context, cm ginauth.ClaimMetadata) {
	if cm.Subject != "" {
		c.Set(contextKeySubject, cm.Subject)
	}

	if cm.User != "" {
		c.Set(contextKeyUser, cm.User)
	}
}

// VerifyTokenWithScopes satisfies the goauth.GenericAuthMiddleware interface and exists only for
// backwards compatibility with that interface.
func (m *Middleware) VerifyTokenWithScopes(c *gin.Context, scopes []string) (ginauth.ClaimMetadata, error) {
	cm, err := m.VerifyToken(c)
	if err != nil {
		return ginauth.ClaimMetadata{}, err
	}

	c.Set(contextKeySubject, cm.Subject)
	c.Set(contextKeyUser, cm.User)
	c.Set(contextKeyRoles, cm.Roles)

	if err := m.VerifyScopes(c, scopes); err != nil {
		return ginauth.ClaimMetadata{}, err
	}

	return cm, nil
}

// VerifyToken verifies a JWT token gotten from the gin.Context object. This does not validate roles claims/scopes.
// This implements the GenericMiddleware interface
func (m *Middleware) VerifyToken(c *gin.Context) (ginauth.ClaimMetadata, error) {
	authHeader := c.Request.Header.Get("Authorization")

	if authHeader == "" {
		return ginauth.ClaimMetadata{}, ginauth.NewAuthenticationError("missing authorization header, expected format: \"Bearer token\"")
	}

	authHeaderParts := strings.SplitN(authHeader, " ", expectedAuthHeaderParts)

	if !(len(authHeaderParts) == expectedAuthHeaderParts && strings.ToLower(authHeaderParts[0]) == "bearer") {
		return ginauth.ClaimMetadata{}, ginauth.NewAuthenticationError("invalid authorization header, expected format: \"Bearer token\"")
	}

	rawToken := authHeaderParts[1]

	tok, err := jwt.ParseSigned(rawToken)
	if err != nil {
		return ginauth.ClaimMetadata{}, ginauth.NewAuthenticationError("unable to parse auth token")
	}

	if tok.Headers[0].KeyID == "" {
		return ginauth.ClaimMetadata{}, ginauth.NewAuthenticationError("unable to parse auth token header")
	}

	key := m.getJWKS(tok.Headers[0].KeyID)
	if key == nil {
		return ginauth.ClaimMetadata{}, ginauth.NewInvalidSigningKeyError()
	}

	cl := jwt.Claims{}
	sc := map[string]interface{}{}

	if err := tok.Claims(key, &cl, &sc); err != nil {
		return ginauth.ClaimMetadata{}, ginauth.NewAuthenticationError("unable to validate auth token")
	}

	err = cl.Validate(jwt.Expected{
		Issuer:   m.config.Issuer,
		Audience: jwt.Audience{m.config.Audience},
		Time:     time.Now(),
	})
	if err != nil {
		return ginauth.ClaimMetadata{}, ginauth.NewTokenValidationError(err)
	}

	var roles []string
	switch r := sc[m.config.RolesClaim].(type) {
	case string:
		roles = strings.Split(r, " ")
	case []interface{}:
		for _, i := range r {
			roles = append(roles, i.(string))
		}
	}

	var user string
	switch u := sc[m.config.UsernameClaim].(type) {
	case string:
		user = u
	default:
		user = cl.Subject
	}

	return ginauth.ClaimMetadata{Subject: cl.Subject, User: user, Roles: roles}, nil
}

// AuthRequired provides a middleware that ensures a request has authentication.  In order to
// validate scopes, you also need to call RequireScopes().
func (m *Middleware) AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !m.config.Enabled {
			return
		}

		cm, err := m.VerifyToken(c)
		if err != nil {
			ginauth.AbortBecauseOfError(c, err)
			return
		}

		c.Set(contextKeySubject, cm.Subject)
		c.Set(contextKeyUser, cm.User)
		c.Set(contextKeyRoles, cm.Roles)
	}
}

// RequiredScopes provides middleware that validates that the passed list of scopes
// are included in the role claims by checking the values on context.
func (m *Middleware) RequiredScopes(scopes []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !m.config.Enabled {
			return
		}

		if err := m.VerifyScopes(c, scopes); err != nil {
			ginauth.AbortBecauseOfError(c, err)
			return
		}
	}
}

// VerifyScopes verifies role claims added to the gin.Context object.
// This implements the GenericMiddleware interface
func (m *Middleware) VerifyScopes(c *gin.Context, scopes []string) error {
	roles := c.GetStringSlice("jwt.roles")

	if !hasScope(roles, scopes) {
		return ginauth.NewAuthorizationError("not authorized, missing required scope")
	}

	return nil
}

func (m *Middleware) refreshJWKS() error {
	resp, err := http.Get(m.config.JWKSURI) //nolint:noctx
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s", ginauth.ErrMiddlewareRemote, resp.Body)
	}

	return json.NewDecoder(resp.Body).Decode(&m.cachedJWKS)
}

func (m *Middleware) getJWKS(kid string) *jose.JSONWebKey {
	keys := m.cachedJWKS.Key(kid)
	if len(keys) == 0 {
		// couldn't find the signing key in our cache, refresh cache and search again
		if err := m.refreshJWKS(); err != nil {
			return nil
		}

		keys = m.cachedJWKS.Key(kid)
		if len(keys) == 0 {
			return nil
		}
	}

	return &keys[0]
}

func hasScope(have, needed []string) bool {
	neededMap := make(map[string]bool)
	for _, s := range needed {
		neededMap[s] = true
	}

	for _, s := range have {
		if neededMap[s] {
			return true
		}
	}

	return false
}

// GetSubject will return the JWT subject that is saved in the request. This requires that authentication of the request
// has already occurred. If authentication failed or there isn't a user, an empty string is returned. This returns
// whatever value was in the JWT subject field and might not be a human readable value
func GetSubject(c *gin.Context) string {
	return c.GetString(contextKeySubject)
}

// GetUser will return the JWT user that is saved in the request. This requires that authentication of the request
// has already occurred. If authentication failed or there isn't a user an empty string is returned.
func GetUser(c *gin.Context) string {
	return c.GetString(contextKeyUser)
}
