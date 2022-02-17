package ginauth

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

// AbortBecauseOfError aborts a gin context based on a given error
func AbortBecauseOfError(c *gin.Context, err error) {
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
