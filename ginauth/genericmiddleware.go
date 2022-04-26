package ginauth

import (
	"github.com/gin-gonic/gin"
)

// ClaimMetadata returns the minimal relevant information so middleware
// can set the appropriate metadata to a context (e.g. a gin.Context)
type ClaimMetadata struct {
	Subject string
	User    string
	Roles   []string
}

// GenericAuthMiddleware defines middleware that verifies a token coming from a gin.Context.
// Note that this can be stacked together using the MultiTokenMiddleware construct.
type GenericAuthMiddleware interface {
	VerifyTokenWithScopes(*gin.Context, []string) (ClaimMetadata, error)
	SetMetadata(*gin.Context, ClaimMetadata)
}
