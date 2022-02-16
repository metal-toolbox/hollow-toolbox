package ginjwt

import (
	"errors"
	"fmt"
	"net/http"
)

var (
	// ErrInvalidMiddlewareReference the middleware added was invalid
	ErrInvalidMiddlewareReference = errors.New("invalid middleware")

	// ErrMiddlewareRemote is the error returned when the middleware couldn't contact the remote endpoint
	ErrMiddlewareRemote = errors.New("middleware setup")

	// ErrInvalidSigningKey is the error returned when a token can not be verified because the signing key in invalid
	ErrInvalidSigningKey = errors.New("invalid token signing key")

	// ErrInvalidAudience is the error returned when the audience of the token isn't what we expect
	ErrInvalidAudience = errors.New("invalid JWT audience")

	// ErrInvalidIssuer is the error returned when the issuer of the token isn't what we expect
	ErrInvalidIssuer = errors.New("invalid JWT issuer")

	// ErrAuthentication defines a generic authentication error. This specifies that we couldn't
	// validate a token for some reason. This is not to be used as-is but is useful for type
	// comparison with the `AuthError` struct.
	ErrAuthentication = errors.New("authentication error")
)

// AuthError represents an auth error coming from a middleware function
type AuthError struct {
	HTTPErrorCode int
	err           error
}

// NewAuthenticationError returns an authentication error which is due
// to not being able to determine who's the requestor (e.g. authentication error)
func NewAuthenticationError(msg string) *AuthError {
	return &AuthError{
		HTTPErrorCode: http.StatusUnauthorized,
		// nolint:goerr113
		err: errors.New(msg),
	}
}

// NewAuthorizationError returns an authorization error which is due to
// not being able to determine what the requestor can do (e.g. authorization error)
func NewAuthorizationError(msg string) *AuthError {
	return &AuthError{
		HTTPErrorCode: http.StatusForbidden,
		// nolint:goerr113
		err: errors.New(msg),
	}
}

// Error ensures AuthenticationError implements the error interface
func (ae *AuthError) Error() string {
	return ae.err.Error()
}

// Unwrap ensures that we're able to verify that this is indeed
// an authentication error
func (ae *AuthError) Unwrap() error {
	return ErrAuthentication
}

// TokenValidationError specifies that there was an authentication error
// due to the token being invalid
type TokenValidationError struct {
	AuthError
}

// Error ensures AuthenticationError implements the error interface
func (tve *TokenValidationError) Error() string {
	return fmt.Sprintf("invalid auth token: %s", &tve.AuthError)
}

// Unwrap allows TokenValidationError to be detected as an AuthError.
func (tve *TokenValidationError) Unwrap() error {
	return &tve.AuthError
}

// NewTokenValidationError returns a TokenValidationError that wraps the given error
func NewTokenValidationError(err error) error {
	return &TokenValidationError{
		AuthError: AuthError{
			HTTPErrorCode: http.StatusUnauthorized,
			err:           err,
		},
	}
}

// NewInvalidSigningKeyError returns an AuthError that indicates
// that the signing key used to validate the token was not valid
func NewInvalidSigningKeyError() error {
	return &AuthError{
		HTTPErrorCode: http.StatusUnauthorized,
		err:           ErrInvalidSigningKey,
	}
}
