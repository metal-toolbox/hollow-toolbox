package ginjwt

import (
	"github.com/pkg/errors"
	"go.hollow.sh/toolbox/ginauth"
)

// NewMultiTokenMiddlewareFromConfigs builds a MultiTokenMiddleware object from multiple AuthConfigs.
func NewMultiTokenMiddlewareFromConfigs(cfgs ...AuthConfig) (*ginauth.MultiTokenMiddleware, error) {
	if len(cfgs) == 0 {
		return nil, errors.Wrap(ErrInvalidAuthConfig, "configuration empty")
	}

	mtm := &ginauth.MultiTokenMiddleware{}

	for _, cfg := range cfgs {
		middleware, err := NewAuthMiddleware(cfg)
		if err != nil {
			return nil, err
		}

		if err := mtm.Add(middleware); err != nil {
			return nil, err
		}
	}

	return mtm, nil
}
