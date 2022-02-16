package ginjwt

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

// NewMultiTokenMiddlwareFromConfigs builds a MultiTokenMiddleware object from multiple AuthConfigs.
func NewMultiTokenMiddlwareFromConfigs(cfgs ...AuthConfig) (*MultiTokenMiddleware, error) {
	mtm := &MultiTokenMiddleware{}
	mtm.verifiers = make([]GenericAuthMiddleware, len(cfgs))

	for idx, cfg := range cfgs {
		middleware, err := NewAuthMiddleware(cfg)
		if err != nil {
			return nil, err
		}

		mtm.verifiers[idx] = middleware
	}

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

		type aggregatedResult struct {
			cm  ClaimMetadata
			err error
		}

		res := make(chan aggregatedResult, len(mtm.verifiers))

		wg.Add(len(mtm.verifiers))

		for _, verifier := range mtm.verifiers {
			go func(v GenericAuthMiddleware, r chan<- aggregatedResult) {
				defer wg.Done()

				c, err := v.VerifyToken(c, scopes)

				r <- aggregatedResult{c, err}
			}(verifier, res)
		}

		wg.Wait()
		close(res)

		var surfacingErr error

		for result := range res {
			if result.err == nil {
				if result.cm.Subject != "" {
					c.Set(contextKeySubject, result.cm.Subject)
				}

				if result.cm.User != "" {
					c.Set(contextKeyUser, result.cm.User)
				}

				// NOTE(jaosorior): This takes the first non-error as a success.
				// It would be quite strange if we would get multiple successes.
				return
			}

			// initialize surfacingErr.
			if surfacingErr == nil {
				surfacingErr = result.err
				continue
			}

			// If we previously had an error related to having an invalid signing key
			// we overwrite the error to be surfaced. We care more about other types of
			// errors, such as not having the appropriate scope
			if errors.Is(surfacingErr, ErrInvalidSigningKey) {
				surfacingErr = result.err
			}
		}

		if surfacingErr != nil {
			abortBecauseOfError(c, surfacingErr)
		}
	}
}
