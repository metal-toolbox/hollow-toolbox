package ginauth

import (
	"errors"
	"fmt"
	"sync"

	"github.com/gin-gonic/gin"
)

// MultiTokenMiddleware Allows for concurrently verifying a token
// using different middleware implementations. This relies on implementing
// the GenericAuthMiddleware interface.
// Only the first detected success will be taken into account.
// Note that middleware objects don't have to be of Middleware type, that's
// only one object that implements the interface.
type MultiTokenMiddleware struct {
	verifiers []GenericAuthMiddleware
}

// NewMultiTokenMiddleware builds a MultiTokenMiddleware object from multiple AuthConfigs.
func NewMultiTokenMiddleware() (*MultiTokenMiddleware, error) {
	mtm := &MultiTokenMiddleware{}
	mtm.verifiers = make([]GenericAuthMiddleware, 0)

	return mtm, nil
}

// Add will append another middleware object (or verifier) to the list
// which we'll use to check concurrently
func (mtm *MultiTokenMiddleware) Add(middleware GenericAuthMiddleware) error {
	if middleware == nil {
		return fmt.Errorf("%w: %s", ErrInvalidMiddlewareReference, "The middleware reference can't be nil")
	}

	mtm.verifiers = append(mtm.verifiers, middleware)

	return nil
}

// AuthRequired is similar to the `AuthRequired` function from the Middleware type
// in the sense that it'll evaluate the scopes and the token coming from the context.
// However, this will concurrently evaluate them with the middlewares configured in this
// struct
func (mtm *MultiTokenMiddleware) AuthRequired(scopes []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var wg sync.WaitGroup

		res := make(chan error, len(mtm.verifiers))

		wg.Add(len(mtm.verifiers))

		for _, verifier := range mtm.verifiers {
			go func(v GenericAuthMiddleware, c *gin.Context, r chan<- error) {
				defer wg.Done()

				cm, err := v.VerifyTokenWithScopes(c, scopes)

				if err != nil {
					v.SetMetadata(c, cm)
				}

				r <- err
			}(verifier, c, res)
		}

		wg.Wait()
		close(res)

		var surfacingErr error

		for err := range res {
			if err == nil {
				// NOTE(jaosorior): This takes the first non-error as a success.
				// It would be quite strange if we would get multiple successes.
				return
			}

			// initialize surfacingErr.
			if surfacingErr == nil {
				surfacingErr = err
				continue
			}

			// If we previously had an error related to having an invalid signing key
			// we overwrite the error to be surfaced. We care more about other types of
			// errors, such as not having the appropriate scope
			// Also, if we previously had an error with the remote endpoint, we override the error.
			// This might be a very general error and more specific ones are preferred
			// for surfacing.
			if errors.Is(surfacingErr, ErrMiddlewareRemote) || errors.Is(surfacingErr, ErrInvalidSigningKey) {
				surfacingErr = err
			}
		}

		if surfacingErr != nil {
			AbortBecauseOfError(c, surfacingErr)
		}
	}
}
