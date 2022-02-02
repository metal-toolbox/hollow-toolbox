package ginjwt

import (
	"errors"
)

var (
	// ErrInvalidAudience is the error returned when the audience of the token isn't what we expect
	ErrInvalidAudience = errors.New("invalid JWT audience")

	// ErrInvalidIssuer is the error returned when the issuer of the token isn't what we expect
	ErrInvalidIssuer = errors.New("invalid JWT issuer")

	// ErrMissingIssuerFlag is an error eturned when the issuer isn't provided via a command line flag.
	ErrMissingIssuerFlag = errors.New("issuer wasn't provided")

	// ErrMissingJWKURIFlag is an error eturned when the JWK URI isn't provided via a command line flag.
	ErrMissingJWKURIFlag = errors.New("JWK URI wasn't provided")

	// ErrIssuersDontMatchJWKURIs is the error returned when the number of issuers given
	// as command line flags don't match the number of JWK URIs given.
	ErrIssuersDontMatchJWKURIs = errors.New("the number of issuers doesn't match the number of JWK URIs")
)
