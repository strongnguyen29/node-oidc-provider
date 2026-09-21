package models

// Session represents a user login session.
type Session struct {
ID        string
AccountID string
LoginTime int64
Clients   map[string]*ClientSession
}

// ClientSession tracks per-client consent state within a session.
type ClientSession struct {
GrantID   string
Consented []string
}

// AuthorizationCode is an OAuth2 authorization code.
type AuthorizationCode struct {
Code                string
ClientID            string
RedirectURI         string
Scopes              []string
CodeChallenge       string
CodeChallengeMethod string
Nonce               string
AccountID           string
SessionID           string
GrantID             string
CreatedAt           int64
ExpiresAt           int64
Consumed            bool
}

// RefreshToken is an opaque refresh token stored in the adapter.
type RefreshToken struct {
ID        string
AccountID string
ClientID  string
Scopes    []string
GrantID   string
CreatedAt int64
ExpiresAt int64
Consumed  bool
}

// DeviceCode holds state for the device authorization flow.
type DeviceCode struct {
DeviceCode string
UserCode   string
ClientID   string
Scopes     []string
AccountID  string
GrantID    string
Verified   bool
Denied     bool
CreatedAt  int64
ExpiresAt  int64
}

// Grant represents a resource owner authorization grant.
type Grant struct {
ID        string
AccountID string
ClientID  string
Scopes    []string
CreatedAt int64
}

// Interaction holds state for a user-facing interaction (login/consent).
type Interaction struct {
UID       string
Prompt    string
ClientID  string
Params    map[string]string
Result    *InteractionResult
CreatedAt int64
ExpiresAt int64
AccountID string
SessionID string
}

// InteractionResult holds the outcome of an interaction.
type InteractionResult struct {
Login   *LoginResult
Consent *ConsentResult
}

// LoginResult holds the result of a login interaction.
type LoginResult struct {
AccountID string
}

// ConsentResult holds the result of a consent interaction.
type ConsentResult struct {
GrantedScopes  []string
RejectedScopes []string
}
