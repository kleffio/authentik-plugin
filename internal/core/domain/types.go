package domain

// TokenSet is the OAuth2/OIDC token bundle returned after a successful login.
type TokenSet struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	TokenType    string
	ExpiresIn    int64
	Scope        string
}

// TokenClaims carries verified identity extracted from a validated JWT.
type TokenClaims struct {
	Subject  string
	Username string
	Email    string
	Roles    []string
}

// OIDCConfig holds the OIDC discovery parameters the frontend needs.
type OIDCConfig struct {
	Authority             string // browser-reachable issuer URL
	ClientID              string
	JwksURI               string
	AuthMode              string // "headless" or "redirect"
	TokenEndpoint         string // public token endpoint (browser-reachable)
	InternalTokenEndpoint string // Docker-internal token endpoint for server-side proxy
	EndSessionEndpoint    string // public end-session (logout) endpoint
}

// RegisterRequest holds fields required to create a new user.
type RegisterRequest struct {
	Username  string
	Email     string
	Password  string
	FirstName string
	LastName  string
}

// Session represents an active user session.
type Session struct {
	ID        string
	IPAddress string
	Browser   string
	Started   int64
	LastSeen  int64
}
