package handlers

import (
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/strongnguyen29/go-oidc-provider/internal/config"
	"github.com/strongnguyen29/go-oidc-provider/internal/crypto"
	"github.com/strongnguyen29/go-oidc-provider/internal/logging"
	"github.com/strongnguyen29/go-oidc-provider/internal/middleware"
	"github.com/strongnguyen29/go-oidc-provider/internal/models"
	"github.com/strongnguyen29/go-oidc-provider/internal/store"
	"github.com/strongnguyen29/go-oidc-provider/internal/views"
)

var (
	loginTmpl         = template.Must(template.New("login").ParseFS(views.FS, "login.html"))
	consentTmpl       = template.Must(template.New("consent").ParseFS(views.FS, "consent.html"))
	selectAccountTmpl = template.Must(template.New("select_account").ParseFS(views.FS, "select_account.html"))
	errorTmpl         = template.Must(template.New("error").ParseFS(views.FS, "error.html"))
)

// NewInteractionGetHandler handles GET /interaction/{uid}. The session
// middleware is used to mint a CSRF token bound to the interaction uid that
// must be echoed back on the matching POST.
func NewInteractionGetHandler(cfg *config.Config, adapter store.Adapter, sm *middleware.SessionMiddleware) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid := chi.URLParam(r, "uid")
		log := logging.FromContext(r.Context())
		raw, err := adapter.Find(r.Context(), "interaction:"+uid)
		if err != nil {
			log.LogAttrs(r.Context(), slog.LevelWarn, "interaction_not_found",
				slog.String("uid", uid),
			)
			errorTmpl.ExecuteTemplate(w, "error.html", map[string]string{
				"Title":       "Interaction Not Found",
				"Description": "This interaction has expired or does not exist.",
			})
			return
		}
		interaction, ok := raw.(*models.Interaction)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		log.LogAttrs(r.Context(), slog.LevelDebug, "interaction_view",
			slog.String("uid", uid),
			slog.String("prompt", interaction.Prompt),
			slog.String("client_id", interaction.ClientID),
		)

		csrf := sm.CSRFToken(uid)
		w.Header().Set("Content-Type", "text/html")
		switch interaction.Prompt {
		case "login":
			loginTmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{
				"UID":       uid,
				"CSRFToken": csrf,
			})
		case "consent":
			scopes := strings.Fields(interaction.Params["scope"])
			consentTmpl.ExecuteTemplate(w, "consent.html", map[string]interface{}{
				"UID":       uid,
				"ClientID":  interaction.ClientID,
				"Scopes":    scopes,
				"CSRFToken": csrf,
			})
		case "select_account":
			selectAccountTmpl.ExecuteTemplate(w, "select_account.html", map[string]interface{}{
				"UID":       uid,
				"AccountID": interaction.AccountID,
				"CSRFToken": csrf,
			})
		default:
			errorTmpl.ExecuteTemplate(w, "error.html", map[string]string{
				"Title":       "Unknown Prompt",
				"Description": "Unknown interaction type.",
			})
		}
	}
}

// NewInteractionLoginHandler handles POST /interaction/{uid}/login.
func NewInteractionLoginHandler(cfg *config.Config, ks *crypto.Keystore, adapter store.Adapter, sm *middleware.SessionMiddleware) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid := chi.URLParam(r, "uid")
		log := logging.FromContext(r.Context())
		raw, err := adapter.Find(r.Context(), "interaction:"+uid)
		if err != nil {
			log.LogAttrs(r.Context(), slog.LevelWarn, "interaction_login_uid_not_found",
				slog.String("uid", uid))
			w.WriteHeader(http.StatusNotFound)
			return
		}
		interaction, ok := raw.(*models.Interaction)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if !sm.ValidateCSRF(uid, r.FormValue("csrf_token")) {
			log.LogAttrs(r.Context(), slog.LevelWarn, "csrf_validation_failed",
				slog.String("flow", "interaction_login"),
				slog.String("uid", uid),
			)
			middleware.WriteOAuthError(w, http.StatusForbidden, "invalid_request", "csrf token invalid")
			return
		}

		// Handle select_account: user picked an existing session.
		if r.FormValue("use_existing") == "1" && interaction.SessionID != "" {
			rawSess, err := adapter.Find(r.Context(), "session:"+interaction.SessionID)
			if err == nil {
				if sess, ok := rawSess.(*models.Session); ok {
					sm.SaveSessionID(w, sess.ID)
					// "select_account" is now satisfied — strip it before the
					// next dispatch so we don't loop back into account picker.
					clearPromptValue(interaction.Params, "select_account")
					client := cfg.FindClient(interaction.ClientID)
					if client == nil {
						middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_client", "client missing")
						return
					}
					dispatchNext(w, r, cfg, ks, adapter, sm, client, sess, interaction.Params)
					return
				}
			}
		}

		login := r.FormValue("login")
		password := r.FormValue("password")

		if cfg.AuthenticateAccount == nil {
			renderLoginError(w, uid, sm.CSRFToken(uid), "Authentication not configured")
			return
		}

		account, err := cfg.AuthenticateAccount(r.Context(), login, password)
		if err != nil || account == nil {
			log.LogAttrs(r.Context(), slog.LevelWarn, "interaction_login_failed",
				slog.String("uid", uid),
				slog.String("login", login),
				slog.Bool("auth_error", err != nil),
			)
			renderLoginError(w, uid, sm.CSRFToken(uid), "Invalid username or password")
			return
		}
		log.LogAttrs(r.Context(), slog.LevelInfo, "interaction_login_ok",
			slog.String("uid", uid),
			slog.String("account_id", account.Sub),
			slog.String("client_id", interaction.ClientID),
		)

		// Create or update session.
		sessionID := sm.GetSessionID(r)
		var session *models.Session
		if sessionID != "" {
			if rawSess, err := adapter.Find(r.Context(), "session:"+sessionID); err == nil {
				session, _ = rawSess.(*models.Session)
			}
		}
		if session == nil {
			session = &models.Session{
				ID:        uuid.New().String(),
				Clients:   make(map[string]*models.ClientSession),
				LoginTime: time.Now().Unix(),
			}
		}
		session.AccountID = account.Sub
		adapter.Upsert(r.Context(), "session:"+session.ID, session, 24*time.Hour)
		sm.SaveSessionID(w, session.ID)

		// Check if this is a device flow login.
		if deviceUserCode := interaction.Params["device_user_code"]; deviceUserCode != "" {
			deviceCodeID := interaction.Params["device_code_id"]
			if rawDC, err := adapter.Find(r.Context(), "device:"+deviceCodeID); err == nil {
				if dc, ok := rawDC.(*models.DeviceCode); ok {
					dc.Verified = true
					dc.AccountID = account.Sub
					adapter.Upsert(r.Context(), "device:"+dc.DeviceCode, dc, cfg.DeviceCodeTTL)
				}
			}
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<!DOCTYPE html><html><body><h2>Device authorized!</h2><p>You may close this window and return to your device.</p></body></html>`))
			return
		}

		// Update interaction and dispatch directly to the next stage
		// (consent / completion) instead of bouncing back to /authorize.
		interaction.AccountID = account.Sub
		interaction.SessionID = session.ID
		if interaction.Result == nil {
			interaction.Result = &models.InteractionResult{}
		}
		interaction.Result.Login = &models.LoginResult{AccountID: account.Sub}
		// Drop the resolved prompt — uses the interaction's own Prompt value
		// to handle both "login" and "select_account" → new login uniformly.
		clearPromptValue(interaction.Params, interaction.Prompt)
		adapter.Upsert(r.Context(), "interaction:"+uid, interaction, 10*time.Minute)

		client := cfg.FindClient(interaction.ClientID)
		if client == nil {
			middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_client", "client missing")
			return
		}
		dispatchNext(w, r, cfg, ks, adapter, sm, client, session, interaction.Params)
	}
}

// NewInteractionConfirmHandler handles POST /interaction/{uid}/confirm.
func NewInteractionConfirmHandler(cfg *config.Config, ks *crypto.Keystore, adapter store.Adapter, sm *middleware.SessionMiddleware) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid := chi.URLParam(r, "uid")
		log := logging.FromContext(r.Context())
		raw, err := adapter.Find(r.Context(), "interaction:"+uid)
		if err != nil {
			log.LogAttrs(r.Context(), slog.LevelWarn, "interaction_confirm_uid_not_found",
				slog.String("uid", uid))
			w.WriteHeader(http.StatusNotFound)
			return
		}
		interaction, ok := raw.(*models.Interaction)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if !sm.ValidateCSRF(uid, r.FormValue("csrf_token")) {
			log.LogAttrs(r.Context(), slog.LevelWarn, "csrf_validation_failed",
				slog.String("flow", "interaction_confirm"),
				slog.String("uid", uid),
			)
			middleware.WriteOAuthError(w, http.StatusForbidden, "invalid_request", "csrf token invalid")
			return
		}

		grantedScopes := r.Form["granted_scopes"]
		log.LogAttrs(r.Context(), slog.LevelInfo, "interaction_consent_recorded",
			slog.String("uid", uid),
			slog.String("client_id", interaction.ClientID),
			slog.String("account_id", interaction.AccountID),
			slog.Any("granted_scopes", grantedScopes),
		)

		// Load session and update consent. Keep a reference for dispatchNext
		// — the authorization completion needs the same in-memory snapshot
		// that just got the new grant applied.
		sessionID := interaction.SessionID
		if sessionID == "" {
			sessionID = sm.GetSessionID(r)
		}

		var session *models.Session
		if sessionID != "" {
			if rawSess, err := adapter.Find(r.Context(), "session:"+sessionID); err == nil {
				if sess, ok := rawSess.(*models.Session); ok {
					if sess.Clients == nil {
						sess.Clients = make(map[string]*models.ClientSession)
					}
					cs := sess.Clients[interaction.ClientID]
					if cs == nil {
						cs = &models.ClientSession{}
						sess.Clients[interaction.ClientID] = cs
					}
					cs.Consented = grantedScopes
					adapter.Upsert(r.Context(), "session:"+sess.ID, sess, 24*time.Hour)
					session = sess
				}
			}
		}
		if session == nil {
			middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "session missing")
			return
		}

		// Update interaction result.
		if interaction.Result == nil {
			interaction.Result = &models.InteractionResult{}
		}
		interaction.Result.Consent = &models.ConsentResult{
			GrantedScopes: grantedScopes,
		}
		clearPromptValue(interaction.Params, "consent")
		adapter.Upsert(r.Context(), "interaction:"+uid, interaction, 10*time.Minute)

		client := cfg.FindClient(interaction.ClientID)
		if client == nil {
			middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_client", "client missing")
			return
		}
		dispatchNext(w, r, cfg, ks, adapter, sm, client, session, interaction.Params)
	}
}

// NewInteractionAbortHandler handles POST /interaction/{uid}/abort.
func NewInteractionAbortHandler(cfg *config.Config, adapter store.Adapter, sm *middleware.SessionMiddleware) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid := chi.URLParam(r, "uid")
		log := logging.FromContext(r.Context())
		raw, err := adapter.Find(r.Context(), "interaction:"+uid)
		if err != nil {
			log.LogAttrs(r.Context(), slog.LevelWarn, "interaction_abort_uid_not_found",
				slog.String("uid", uid))
			w.WriteHeader(http.StatusNotFound)
			return
		}
		interaction, ok := raw.(*models.Interaction)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !sm.ValidateCSRF(uid, r.FormValue("csrf_token")) {
			log.LogAttrs(r.Context(), slog.LevelWarn, "csrf_validation_failed",
				slog.String("flow", "interaction_abort"),
				slog.String("uid", uid),
			)
			middleware.WriteOAuthError(w, http.StatusForbidden, "invalid_request", "csrf token invalid")
			return
		}
		log.LogAttrs(r.Context(), slog.LevelInfo, "interaction_aborted",
			slog.String("uid", uid),
			slog.String("client_id", interaction.ClientID),
		)
		redirectURI := interaction.Params["redirect_uri"]
		state := interaction.Params["state"]
		adapter.Destroy(r.Context(), "interaction:"+uid)
		var registeredURIs []string
		if interactionClient := cfg.FindClient(interaction.ClientID); interactionClient != nil {
			registeredURIs = interactionClient.RedirectURIs
		}
		middleware.RedirectOAuthError(w, r, redirectURI, registeredURIs, "access_denied", "user denied access", state)
	}
}

func renderLoginError(w http.ResponseWriter, uid, csrf, errMsg string) {
	w.Header().Set("Content-Type", "text/html")
	loginTmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{
		"UID":       uid,
		"CSRFToken": csrf,
		"Error":     errMsg,
	})
}
