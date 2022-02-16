package ginjwt

import (
	"errors"
)

var (
	// ErrInvalidAudience is the error returned when the audience of the token isn't what we expect
	ErrInvalidAudience = errors.New("invalid JWT audience")

	// ErrInvalidIssuer is the error returned when the issuer of the token isn't what we expect
	ErrInvalidIssuer = errors.New("invalid JWT issuer")
)
