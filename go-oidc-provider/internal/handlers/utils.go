package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/strongnguyen29/go-oidc-provider/internal/config"
	"github.com/strongnguyen29/go-oidc-provider/internal/crypto"
	"github.com/strongnguyen29/go-oidc-provider/internal/logging"
	"github.com/strongnguyen29/go-oidc-provider/internal/middleware"
	"github.com/strongnguyen29/go-oidc-provider/internal/models"
	"github.com/strongnguyen29/go-oidc-provider/internal/store"
)

// containsString returns true if slice contains s.
func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// responseTypeAllowed reports whether a requested response_type matches one
// of the entries registered for the client. The OAuth/OIDC spec treats the
// space-separated tokens as an unordered set ("token id_token" ≡
// "id_token token"), so both sides are normalised by sorting before compare.
func responseTypeAllowed(requested string, allowed []string) bool {
	want := normalizeResponseType(requested)
	if want == "" {
		return false
	}
	for _, candidate := range allowed {
		if normalizeResponseType(candidate) == want {
			return true
		}
	}
	return false
}

func normalizeResponseType(rt string) string {
	tokens := strings.Fields(rt)
	if len(tokens) == 0 {
		return ""
	}
	sortStrings(tokens)
	return strings.Join(tokens, " ")
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// hasAllScopes returns true if all requested scopes are in consented.
func hasAllScopes(consented, requested []string) bool {
	m := make(map[string]bool, len(consented))
	for _, s := range consented {
		m[s] = true
	}
	for _, s := range requested {
		if !m[s] {
			return false
		}
	}
	return true
}

// dispatchNext evaluates the current auth state and either creates the next
// interaction stage (login / consent / select_account) or completes the auth
// flow by issuing the authorization code or implicit-flow tokens.
//
// The /authorize handler delegates here on first hit; the interaction
// handlers (login / consent / select_account) also call it directly after
// applying their own state mutation, allowing a single 302 to the next
// step instead of a 302 → /authorize → 302 round-trip.
//
// Caller contract: client must be non-nil and already validated (redirect_uri
// in client.RedirectURIs, response_type allowed). session may be nil when
// the user is not yet authenticated. params holds the original /authorize
// query parameters (including any prompt values still pending). Resolved
// prompt values must already be cleared from params["prompt"] by the caller
// (see clearPromptValue) so a satisfied stage is not re-entered.
func dispatchNext(
	w http.ResponseWriter, r *http.Request,
	cfg *config.Config, ks *crypto.Keystore, adapter store.Adapter, sm *middleware.SessionMiddleware,
	client *config.ClientConfig, session *models.Session, params map[string]string,
) {
	log := logging.FromContext(r.Context())
	prompt := params["prompt"]
	clientID := params["client_id"]
	scope := params["scope"]

	interactionPrompt := ""
	switch {
	case session == nil || prompt == "login":
		interactionPrompt = "login"
	case prompt == "select_account":
		interactionPrompt = "select_account"
	default:
		cs := session.Clients[clientID]
		requestedScopes := strings.Fields(scope)
		needsConsent := cs == nil || prompt == "consent" || !hasAllScopes(cs.Consented, requestedScopes)
		// First-party clients ALWAYS skip the consent UI — even when the
		// relying party sends prompt=consent. The operator-controlled
		// IsFirstParty flag is treated as an unconditional trust marker:
		// the user has already opted into the wider product, so re-asking
		// for consent on internal scopes adds friction without security
		// gain. The requested scopes are auto-granted by mutating the
		// client-session record so completeAuthFlow emits the same scope
		// set as if the user had clicked Allow.
		if needsConsent && client.IsFirstParty {
			if session.Clients == nil {
				session.Clients = make(map[string]*models.ClientSession)
			}
			if cs == nil {
				cs = &models.ClientSession{}
				session.Clients[clientID] = cs
			}
			cs.Consented = mergeScopes(cs.Consented, requestedScopes)
			adapter.Upsert(r.Context(), "session:"+session.ID, session, 24*time.Hour)
			log.LogAttrs(r.Context(), slog.LevelInfo, "first_party_auto_consent",
				slog.String("client_id", clientID),
				slog.String("account_id", session.AccountID),
				slog.Any("scopes", requestedScopes),
			)
			needsConsent = false
		}
		if needsConsent {
			interactionPrompt = "consent"
		}
	}

	if interactionPrompt != "" {
		uid := uuid.New().String()
		interaction := &models.Interaction{
			UID:       uid,
			Prompt:    interactionPrompt,
			ClientID:  clientID,
			Params:    params,
			CreatedAt: time.Now().Unix(),
			ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
		}
		if session != nil {
			interaction.AccountID = session.AccountID
			interaction.SessionID = session.ID
		}
		adapter.Upsert(r.Context(), "interaction:"+uid, interaction, 10*time.Minute)
		log.LogAttrs(r.Context(), slog.LevelInfo, "authorize_interaction_created",
			slog.String("uid", uid),
			slog.String("prompt", interactionPrompt),
			slog.String("client_id", clientID),
			slog.Bool("has_session", session != nil),
		)
		http.Redirect(w, r, "/interaction/"+uid, http.StatusFound)
		return
	}

	log.LogAttrs(r.Context(), slog.LevelInfo, "authorize_complete_no_interaction",
		slog.String("client_id", clientID),
		slog.String("account_id", session.AccountID),
		slog.String("response_type", params["response_type"]),
	)
	completeAuthFlow(w, r, cfg, ks, adapter, sm, session, params)
}

// mergeScopes returns the union of base and extra preserving order: every
// element of base first (deduplicated), then any element from extra not
// already present. Used when augmenting an existing client-session consent
// list with newly granted scopes (e.g. first-party auto-consent).
func mergeScopes(base, extra []string) []string {
	seen := make(map[string]struct{}, len(base)+len(extra))
	out := make([]string, 0, len(base)+len(extra))
	for _, s := range base {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, s := range extra {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// intersectScopes returns the requested scopes that the user has consented
// to, preserving the order of `requested`. The result is what should be
// embedded in the authorization code, refresh token, access token claim,
// and ID token. If consented is empty the requested set is returned
// unchanged so callers without a recorded consent still flow through.
func intersectScopes(requested, consented []string) []string {
	if len(consented) == 0 {
		return requested
	}
	allowed := make(map[string]struct{}, len(consented))
	for _, s := range consented {
		allowed[s] = struct{}{}
	}
	out := make([]string, 0, len(requested))
	for _, s := range requested {
		if _, ok := allowed[s]; ok {
			out = append(out, s)
		}
	}
	return out
}

// buildAuthorizeURL reconstructs the /authorize URL from stored params.
func buildAuthorizeURL(params map[string]string) string {
	q := url.Values{}
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	return "/authorize?" + q.Encode()
}

// clearPromptValue removes a single space-separated value from
// params["prompt"] and deletes the key entirely when the resulting
// list is empty. Used by interaction handlers to mark a prompt as
// resolved before the redirect back to /authorize, preventing the
// authorize handler from re-entering the same interaction stage.
func clearPromptValue(params map[string]string, value string) {
	current, ok := params["prompt"]
	if !ok || current == "" {
		return
	}
	parts := strings.Fields(current)
	kept := parts[:0]
	for _, p := range parts {
		if p != value {
			kept = append(kept, p)
		}
	}
	if len(kept) == 0 {
		delete(params, "prompt")
		return
	}
	params["prompt"] = strings.Join(kept, " ")
}

// issueAccessToken creates, signs, and stores an access token.
func issueAccessToken(cfg *config.Config, ks *crypto.Keystore, adapter store.Adapter, ctx context.Context, accountID, clientID, grantID string, scopes []string, now time.Time) (string, string, error) {
	jti := uuid.New().String()
	claims := crypto.AccessTokenClaims{
		Issuer:    cfg.Issuer,
		Subject:   accountID,
		Audience:  []string{cfg.Issuer},
		Scope:     strings.Join(scopes, " "),
		JTI:       jti,
		IssuedAt:  now,
		ExpiresAt: now.Add(cfg.AccessTokenTTL),
		ClientID:  clientID,
	}
	at, err := crypto.IssueAccessToken(ks, claims)
	if err != nil {
		return "", "", err
	}
	adapter.Upsert(ctx, "jti:"+jti, jti, cfg.AccessTokenTTL)
	if grantID != "" {
		grantFamilyAppend(ctx, adapter, grantID, "jti:"+jti, familyTTL(cfg))
	}
	return at, jti, nil
}

// issueRefreshToken creates and stores a refresh token.
func issueRefreshToken(cfg *config.Config, adapter store.Adapter, ctx context.Context, accountID, clientID, grantID string, scopes []string, now time.Time) (string, error) {
	rtID := uuid.New().String()
	rt := &models.RefreshToken{
		ID:        rtID,
		AccountID: accountID,
		ClientID:  clientID,
		Scopes:    scopes,
		GrantID:   grantID,
		CreatedAt: now.Unix(),
		ExpiresAt: now.Add(cfg.RefreshTokenTTL).Unix(),
	}
	if err := adapter.Upsert(ctx, "rt:"+rtID, rt, cfg.RefreshTokenTTL); err != nil {
		return "", err
	}
	if grantID != "" {
		grantFamilyAppend(ctx, adapter, grantID, "rt:"+rtID, familyTTL(cfg))
	}
	return rtID, nil
}

// stringAppender is implemented by adapters that can atomically append to a
// list. Optional interface — falls back to read-modify-write when absent.
type stringAppender interface {
	AppendString(ctx context.Context, id, value string, expiresIn time.Duration) error
}

// familyTTL returns the longest-lived TTL of any token type so the bookkeeping
// entry survives at least as long as the tokens it tracks.
func familyTTL(cfg *config.Config) time.Duration {
	if cfg.RefreshTokenTTL > cfg.AccessTokenTTL {
		return cfg.RefreshTokenTTL
	}
	return cfg.AccessTokenTTL
}

// grantFamilyAppend records a token store key against the grant family so that
// detecting a single replay can revoke every token issued under the same
// grant (RFC 6819 §5.2.2.3).
func grantFamilyAppend(ctx context.Context, adapter store.Adapter, grantID, key string, ttl time.Duration) {
	famKey := "grantfam:" + grantID
	if a, ok := adapter.(stringAppender); ok {
		_ = a.AppendString(ctx, famKey, key, ttl)
		return
	}
	list := []string{}
	if raw, err := adapter.Find(ctx, famKey); err == nil {
		if existing, ok := raw.([]string); ok {
			list = existing
		}
	}
	list = append(list, key)
	_ = adapter.Upsert(ctx, famKey, list, ttl)
}

// validateAccessToken parses tokenStr against the keystore and additionally
// enforces (a) the issuer matches the provider config and (b) the JTI is
// still present in the adapter (i.e. has not been revoked). The returned
// claims map is suitable for direct use by /userinfo and /introspect.
func validateAccessToken(ctx context.Context, ks *crypto.Keystore, adapter store.Adapter, cfg *config.Config, tokenStr string) (gojwt.MapClaims, error) {
	claims, err := crypto.ParseAccessToken(ks, tokenStr)
	if err != nil {
		return nil, err
	}
	iss, _ := (*claims)["iss"].(string)
	if iss != cfg.Issuer {
		return nil, fmt.Errorf("invalid issuer")
	}
	jti, _ := (*claims)["jti"].(string)
	if jti == "" {
		return nil, fmt.Errorf("missing jti")
	}
	if _, err := adapter.Find(ctx, "jti:"+jti); err != nil {
		return nil, fmt.Errorf("token revoked")
	}
	return *claims, nil
}

// revokeGrantFamily destroys every token key recorded under the grant family
// and removes the family bookkeeping entry plus the grant itself. Called on
// replay detection so a leaked token cannot continue to be used and any
// previously-issued sibling tokens are invalidated.
func revokeGrantFamily(ctx context.Context, adapter store.Adapter, grantID string) {
	if grantID == "" {
		return
	}
	famKey := "grantfam:" + grantID
	revoked := 0
	if raw, err := adapter.Find(ctx, famKey); err == nil {
		if list, ok := raw.([]string); ok {
			for _, k := range list {
				_ = adapter.Destroy(ctx, k)
				revoked++
			}
		}
	}
	_ = adapter.Destroy(ctx, famKey)
	_ = adapter.Destroy(ctx, "grant:"+grantID)
	logging.FromContext(ctx).LogAttrs(ctx, slog.LevelWarn, "grant_family_revoked",
		slog.String("grant_id", grantID),
		slog.Int("revoked_keys", revoked),
	)
}

// issueIDToken creates and signs an ID token.
func issueIDToken(cfg *config.Config, ks *crypto.Keystore, ctx context.Context, accountID, clientID, nonce, atHash string, authTime int64, now time.Time) (string, error) {
	extra := map[string]interface{}{}
	if cfg.FindAccount != nil {
		account, err := cfg.FindAccount(ctx, accountID)
		if err == nil && account != nil {
			for k, v := range account.Claims {
				extra[k] = v
			}
		}
	}
	idClaims := crypto.IDTokenClaims{
		Issuer:    cfg.Issuer,
		Subject:   accountID,
		Audience:  []string{clientID},
		Nonce:     nonce,
		AuthTime:  authTime,
		AtHash:    atHash,
		IssuedAt:  now,
		ExpiresAt: now.Add(cfg.AccessTokenTTL),
		Extra:     extra,
	}
	return crypto.IssueIDToken(ks, idClaims)
}

// completeAuthFlow issues tokens/codes and redirects to the redirect_uri.
func completeAuthFlow(
	w http.ResponseWriter, r *http.Request,
	cfg *config.Config, ks *crypto.Keystore, adapter store.Adapter, sm *middleware.SessionMiddleware,
	session *models.Session, params map[string]string,
) {
	responseType := params["response_type"]
	clientID := params["client_id"]
	redirectURI := params["redirect_uri"]
	scope := params["scope"]
	state := params["state"]
	nonce := params["nonce"]
	codeChallenge := params["code_challenge"]
	codeChallengeMethod := params["code_challenge_method"]

	scopes := strings.Fields(scope)
	now := time.Now()

	// Ensure grant and client session exist.
	cs := session.Clients[clientID]
	// Narrow to consented scopes so the authorization code, refresh token, and
	// access token only carry what the user actually approved (RFC 6749 §3.3
	// — "the authorization server MAY ... fully or partially ignore the scope
	// requested by the client"). Without this step a user who consented to
	// `openid` but never `email` would still see `email` in the issued token.
	if cs != nil && len(cs.Consented) > 0 {
		scopes = intersectScopes(scopes, cs.Consented)
	}
	grantID := ""
	if cs != nil {
		grantID = cs.GrantID
	}
	if grantID == "" {
		grantID = uuid.New().String()
		grant := &models.Grant{
			ID:        grantID,
			AccountID: session.AccountID,
			ClientID:  clientID,
			Scopes:    scopes,
			CreatedAt: now.Unix(),
		}
		adapter.Upsert(r.Context(), "grant:"+grantID, grant, 365*24*time.Hour)
		if session.Clients == nil {
			session.Clients = make(map[string]*models.ClientSession)
		}
		if session.Clients[clientID] == nil {
			session.Clients[clientID] = &models.ClientSession{}
		}
		session.Clients[clientID].GrantID = grantID
		adapter.Upsert(r.Context(), "session:"+session.ID, session, 24*time.Hour)
	}

	rtypes := strings.Fields(responseType)
	isImplicit := !containsString(rtypes, "code")

	var accessTokenStr, idTokenStr, authCode string

	if containsString(rtypes, "code") {
		code := uuid.New().String()
		authCode = code
		ac := &models.AuthorizationCode{
			Code:                code,
			ClientID:            clientID,
			RedirectURI:         redirectURI,
			Scopes:              scopes,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			Nonce:               nonce,
			AccountID:           session.AccountID,
			SessionID:           session.ID,
			GrantID:             grantID,
			CreatedAt:           now.Unix(),
			ExpiresAt:           now.Add(cfg.AuthCodeTTL).Unix(),
		}
		adapter.Upsert(r.Context(), "code:"+code, ac, cfg.AuthCodeTTL)
	}

	if containsString(rtypes, "token") {
		at, _, err := issueAccessToken(cfg, ks, adapter, r.Context(), session.AccountID, clientID, grantID, scopes, now)
		if err != nil {
			middleware.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue access token")
			return
		}
		accessTokenStr = at
	}

	if containsString(rtypes, "id_token") {
		atHash := ""
		if accessTokenStr != "" {
			atHash = crypto.ComputeAtHash(accessTokenStr)
		}
		idt, err := issueIDToken(cfg, ks, r.Context(), session.AccountID, clientID, nonce, atHash, session.LoginTime, now)
		if err != nil {
			middleware.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue id_token")
			return
		}
		idTokenStr = idt
	}

	// Use the redirect URI from the trusted registered client list to prevent open redirect.
	trustedRedirectURI := ""
	if client := cfg.FindClient(clientID); client != nil {
		for _, reg := range client.RedirectURIs {
			if reg == redirectURI {
				trustedRedirectURI = reg
				break
			}
		}
	}
	if trustedRedirectURI == "" {
		middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri not registered")
		return
	}
	redirectURL, err := url.Parse(trustedRedirectURI)
	if err != nil {
		middleware.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "invalid redirect_uri")
		return
	}

	if isImplicit {
		frag := url.Values{}
		if accessTokenStr != "" {
			frag.Set("access_token", accessTokenStr)
			frag.Set("token_type", "Bearer")
			frag.Set("expires_in", fmt.Sprintf("%d", int(cfg.AccessTokenTTL.Seconds())))
		}
		if idTokenStr != "" {
			frag.Set("id_token", idTokenStr)
		}
		if state != "" {
			frag.Set("state", state)
		}
		redirectURL.Fragment = frag.Encode()
	} else {
		q := redirectURL.Query()
		if authCode != "" {
			q.Set("code", authCode)
		}
		if state != "" {
			q.Set("state", state)
		}
		redirectURL.RawQuery = q.Encode()
	}

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}
