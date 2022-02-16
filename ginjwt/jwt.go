package ginjwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	contextKeySubject       = "jwt.subject"
	contextKeyUser          = "jwt.user"
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

// VerifyToken verifies a JWT token gotten from the gin.Context object against the given scopes.
// This implements the GenericMiddleware interface
func (m *Middleware) VerifyToken(c *gin.Context, scopes []string) (ClaimMetadata, error) {
	authHeader := c.Request.Header.Get("Authorization")

	if authHeader == "" {
		return ClaimMetadata{}, NewAuthenticationError("missing authorization header, expected format: \"Bearer token\"")
	}

	authHeaderParts := strings.SplitN(authHeader, " ", expectedAuthHeaderParts)

	if !(len(authHeaderParts) == expectedAuthHeaderParts && strings.ToLower(authHeaderParts[0]) == "bearer") {
		return ClaimMetadata{}, NewAuthenticationError("invalid authorization header, expected format: \"Bearer token\"")
	}

	rawToken := authHeaderParts[1]

	tok, err := jwt.ParseSigned(rawToken)
	if err != nil {
		return ClaimMetadata{}, NewAuthenticationError("unable to parse auth token")
	}

	if tok.Headers[0].KeyID == "" {
		return ClaimMetadata{}, NewAuthenticationError("unable to parse auth token header")
	}

	key := m.getJWKS(tok.Headers[0].KeyID)
	if key == nil {
		return ClaimMetadata{}, NewInvalidSigningKeyError()
	}

	cl := jwt.Claims{}
	sc := map[string]interface{}{}

	if err := tok.Claims(key, &cl, &sc); err != nil {
		return ClaimMetadata{}, NewAuthenticationError("unable to validate auth token")
	}

	err = cl.Validate(jwt.Expected{
		Issuer:   m.config.Issuer,
		Audience: jwt.Audience{m.config.Audience},
		Time:     time.Now(),
	})
	if err != nil {
		return ClaimMetadata{}, NewTokenValidationError(err)
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

	if !hasScope(roles, scopes) {
		return ClaimMetadata{}, NewAuthorizationError("not authorized, missing required scope")
	}

	var user string
	switch u := sc[m.config.UsernameClaim].(type) {
	case string:
		user = u
	default:
		user = cl.Subject
	}

	return ClaimMetadata{Subject: cl.Subject, User: user}, nil
}

// AuthRequired provides a middleware that ensures a request has authentication
func (m *Middleware) AuthRequired(scopes []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !m.config.Enabled {
			return
		}

		cm, err := m.VerifyToken(c, scopes)
		if err != nil {
			abortBecauseOfError(c, err)
			return
		}

		c.Set(contextKeySubject, cm.Subject)
		c.Set(contextKeyUser, cm.User)
	}
}

func (m *Middleware) refreshJWKS() error {
	resp, err := http.Get(m.config.JWKSURI) //nolint:noctx
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s", ErrMiddlewareRemote, resp.Body)
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

func abortBecauseOfError(c *gin.Context, err error) {
	var authErr *AuthError

	var validationErr *TokenValidationError

	switch {
	case errors.As(err, &validationErr):
		c.AbortWithStatusJSON(validationErr.HTTPErrorCode, gin.H{"message": "invalid auth token", "error": validationErr.Error()})
	case errors.As(err, &authErr):
		c.AbortWithStatusJSON(authErr.HTTPErrorCode, gin.H{"message": authErr.Error()})
	default:
		// If we can't cast it, unauthorize anyway
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": err.Error()})
	}
}
