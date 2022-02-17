package ginauth

const (
	// AuthRequestVersion1 defines version 1 of the AuthRequest message format
	AuthRequestVersion1 = "v1"
)

// AuthMeta holds metdata for an AuthRequest
type AuthMeta struct {
	Version string `json:"version"`
}

// AuthRequestV1 holds a simple auth request which asks a remote
// endpoint for an authorization decision based on the given scopes
type AuthRequestV1 struct {
	AuthMeta `json:",inline"`
	Scopes   []string `json:"scopes"`
}

// AuthResponseV1 holds a simple auth response which denotes
// the auth decision. Note that the decision will also be
// reflected in the HTTP status code.
type AuthResponseV1 struct {
	AuthMeta `json:",inline"`
	Authed   bool                  `json:"auth"`
	Message  string                `json:"message"`
	Details  *SuccessAuthDetailsV1 `json:"details,omitempty"`
}

// SuccessAuthDetailsV1 holds a simple and successful auth response.
type SuccessAuthDetailsV1 struct {
	Subject string `json:"subject"`
	User    string `json:"user,omitempty"`
}
