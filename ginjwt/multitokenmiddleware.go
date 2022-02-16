package ginjwt

import "go.hollow.sh/toolbox/ginauth"

// NewMultiTokenMiddlwareFromConfigs builds a MultiTokenMiddleware object from multiple AuthConfigs.
func NewMultiTokenMiddlwareFromConfigs(cfgs ...AuthConfig) (*ginauth.MultiTokenMiddleware, error) {
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
