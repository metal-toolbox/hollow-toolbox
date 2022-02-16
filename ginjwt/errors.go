package ginjwt

import (
	"errors"

	"go.hollow.sh/toolbox/ginauth"
)

var (
	// ErrInvalidSigningKey is the error returned when a token can not be verified because the signing key in invalid
	ErrInvalidSigningKey = errors.New("invalid token signing key")

	// ErrInvalidAudience is the error returned when the audience of the token isn't what we expect
	ErrInvalidAudience = errors.New("invalid JWT audience")

	// ErrInvalidIssuer is the error returned when the issuer of the token isn't what we expect
	ErrInvalidIssuer = errors.New("invalid JWT issuer")
)

// NewInvalidSigningKeyError returns an AuthError that indicates
// that the signing key used to validate the token was not valid
func NewInvalidSigningKeyError() error {
	return ginauth.NewAuthenticationErrorFrom(ErrInvalidSigningKey)
}
