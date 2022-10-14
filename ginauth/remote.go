package ginauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	// We might want to standardize these into exportable constants
	contextKeySubject = "jwt.subject"
	contextKeyUser    = "jwt.user"
)

// NewAuthRequestV1FromScopes creates an AuthRequest structure from the given scopes
func NewAuthRequestV1FromScopes(scopes []string) *AuthRequestV1 {
	return &AuthRequestV1{
		AuthMeta: AuthMeta{
			Version: AuthRequestVersion1,
		},
		Scopes: scopes,
	}
}

// RemoteMiddleware defines middleware that relies on a remote endpoint
// in order to get an authorization decision
type RemoteMiddleware struct {
	url     string
	timeout time.Duration
}

// NewRemoteMiddleware returns an instance of RemoteMiddleware
// TODO(jaosorior) Pass in TLS parameters
func NewRemoteMiddleware(url string, timeout time.Duration) *RemoteMiddleware {
	return &RemoteMiddleware{
		url:     url,
		timeout: timeout,
	}
}

// SetMetadata ensures metadata is set in the gin Context
func (rm *RemoteMiddleware) SetMetadata(c *gin.Context, cm ClaimMetadata) {
	if cm.Subject != "" {
		c.Set(contextKeySubject, cm.Subject)
	}

	if cm.User != "" {
		c.Set(contextKeyUser, cm.User)
	}
}

// VerifyTokenWithScopes verifies a given token (from the gin Context) against the given scope
// using a remote server
func (rm *RemoteMiddleware) VerifyTokenWithScopes(c *gin.Context, scopes []string) (ClaimMetadata, error) {
	cli := &http.Client{
		Timeout: rm.timeout,
	}
	origRequest := c.Request
	areq := NewAuthRequestV1FromScopes(scopes)

	reqbody, merr := json.Marshal(areq)
	if merr != nil {
		return ClaimMetadata{}, fmt.Errorf("%w: %s", ErrMiddlewareRemote, merr)
	}

	// We forward the original request method that was done to the target service.
	// That's part of what we're authorizing.
	req, reqerr := http.NewRequestWithContext(c.Request.Context(), origRequest.Method, rm.url, bytes.NewBuffer(reqbody))
	if reqerr != nil {
		return ClaimMetadata{}, fmt.Errorf("%w: %s", ErrMiddlewareRemote, reqerr)
	}

	req.Header.Add("Accept", `application/json`)

	// Forward authorization header
	req.Header.Set("Authorization", origRequest.Header.Get("Authorization"))

	resp, resperr := cli.Do(req)
	if resperr != nil {
		return ClaimMetadata{}, fmt.Errorf("%w: %s", ErrMiddlewareRemote, resperr)
	}

	defer resp.Body.Close()

	body, readerr := io.ReadAll(resp.Body)
	if readerr != nil {
		return ClaimMetadata{}, fmt.Errorf("%w: %s", ErrMiddlewareRemote, readerr)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusUnauthorized {
		return ClaimMetadata{}, fmt.Errorf("%w: %s", ErrMiddlewareRemote, body)
	}

	authResp := AuthResponseV1{}

	unmarshallerr := json.Unmarshal(body, &authResp)
	if unmarshallerr != nil {
		return ClaimMetadata{}, NewAuthenticationError(unmarshallerr.Error())
	}

	if !authResp.Authed {
		return ClaimMetadata{}, NewAuthenticationError(authResp.Message)
	}

	// TODO(jaosorior): Should we fail the request if no appropriate
	// response is provided?
	if authResp.Details == nil {
		// The request was approved but no metadata was given back
		return ClaimMetadata{}, nil
	}

	cm := ClaimMetadata{
		Subject: authResp.Details.Subject,
		User:    authResp.Details.User,
	}
	if authResp.Details.User == "" {
		cm.User = authResp.Details.Subject
	}

	return cm, nil
}

// AuthRequired provides a middleware that ensures a request has authentication
func (rm *RemoteMiddleware) AuthRequired(scopes []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		cm, err := rm.VerifyTokenWithScopes(c, scopes)
		if err != nil {
			AbortBecauseOfError(c, err)
			return
		}

		rm.SetMetadata(c, cm)
	}
}
