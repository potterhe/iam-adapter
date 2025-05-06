package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

type server struct {
	oauth2Config *oauth2.Config
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	stateStorage stateStorage
}

func NewServer() *server {

	ctx := context.TODO()
	provider, err := oidc.NewProvider(ctx, viper.GetString("oidc.issuer"))
	if err != nil {
		// handle error
	}

	clientID := viper.GetString("oidc.client_id")

	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: viper.GetString("oidc.client_secret"),

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}

	var verifier = provider.Verifier(&oidc.Config{ClientID: clientID})

	// @todo config server.stateStorage
	stateStorage := newMemoryStateStorage()

	return &server{
		provider:     provider,
		oauth2Config: &oauth2Config,
		verifier:     verifier,
		stateStorage: stateStorage,
	}
}

// Serve函数用于启动服务器
func (s *server) Serve() {

	// 设置/login/oidc路径的处理函数为s.loginHandler
	http.HandleFunc("/oidc/login", s.loginHandler)
	// 设置/callback/oidc路径的处理函数为s.callbackHandler
	http.HandleFunc("/oidc/callback", s.callbackHandler)
	// 设置/路径的处理函数为s.rootHandler

	// 监听3000端口，启动服务器
	http.ListenAndServe(viper.GetString("server.listen"), nil)
}

func (s *server) loginHandler(w http.ResponseWriter, r *http.Request) {
	// @todo if logined redirect to home
	//fmt.Println(r.Header)
	origRedirectURL := r.URL.Query().Get("redirect_url")
	if origRedirectURL == "" {
		origRedirectURL = "/"
	}

	// @todo generate random state
	state := &state{
		UUID:        uuid.NewString(),
		ctime:       time.Now(),
		redirectURL: origRedirectURL,
	}
	s.stateStorage.Put(state)

	// @todo redirect_url and validate url host must be same as X-Forwarded-Host

	redirectURL := ""
	if viper.GetString("server.proxyHeader") == "xforwarded" {
		xhost := r.Header.Get("X-Forwarded-Host")
		xproto := r.Header.Get("X-Forwarded-Proto")
		xport := r.Header.Get("X-Forwarded-Port")
		redirectURL = fmt.Sprintf("%s://%s:%s/%s", xproto, xhost, xport, "oidc/callback")
		s.oauth2Config.RedirectURL = redirectURL
	}

	http.Redirect(w, r, s.oauth2Config.AuthCodeURL(state.UUID), http.StatusFound)
}

func (s *server) callbackHandler(w http.ResponseWriter, r *http.Request) {
	// Verify state and errors.
	stateID := r.URL.Query().Get("state")
	state := s.stateStorage.Get(stateID)
	if state == nil {
		// handle invalid state
		fmt.Println("invalid state")
		return
	}
	s.stateStorage.Delete(state.UUID)

	code := r.URL.Query().Get("code")
	fmt.Println(code)

	oauth2Token, err := s.oauth2Config.Exchange(r.Context(), code)
	if err != nil {
		fmt.Println(err)
		// handle error
	}

	fmt.Println(oauth2Token)

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		// handle missing token
	}

	// Parse and verify ID Token payload.
	idToken, err := s.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		// handle error
	}

	// Extract custom claims
	var claims struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		// handle error
	}

	// todo check role

	// 放置cookie
	access_token := oauth2Token.AccessToken
	fmt.Println(access_token)
	cookie := &http.Cookie{
		Name:     "Authorization",
		Value:    access_token,
		MaxAge:   int(oauth2Token.ExpiresIn),
		Secure:   true,
		HttpOnly: true,
		Path:     "/",
	}
	http.SetCookie(w, cookie)
	origRedirectURL := state.redirectURL
	http.Redirect(w, r, origRedirectURL, http.StatusTemporaryRedirect)
}
