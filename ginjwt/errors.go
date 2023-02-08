package ginjwt

import (
	"errors"
)

var (
	// ErrInvalidAudience is the error returned when the audience of the token isn't what we expect
	ErrInvalidAudience = errors.New("invalid JWT audience")

	// ErrInvalidIssuer is the error returned when the issuer of the token isn't what we expect
	ErrInvalidIssuer = errors.New("invalid JWT issuer")

	// ErrInvalidAuthConfig is an error returned when the oidc auth config isn't able to be unmarshaled
	ErrInvalidAuthConfig = errors.New("invalid oidc config provided")

	// ErrMissingAuthConfig is an error returned when the oidc auth config isn't provided via a command line flag.
	ErrMissingAuthConfig = errors.New("oidc auth config wasn't provided")

	// ErrMissingIssuerFlag is an error returned when the issuer isn't provided via a command line flag.
	ErrMissingIssuerFlag = errors.New("issuer wasn't provided")

	// ErrMissingJWKURIFlag is an error returned when the JWK URI isn't provided via a command line flag.
	ErrMissingJWKURIFlag = errors.New("JWK URI wasn't provided")

	// ErrJWKSConfigConflict is an error when both JWKSURI and JWKS are set
	ErrJWKSConfigConflict = errors.New("JWKS and JWKSURI can't both be set at the same time")
)
