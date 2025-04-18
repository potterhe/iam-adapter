package server

import (
	"context"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

type server struct {
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
	token        *oauth2.Token
}

func NewServer() *server {

	ctx := context.TODO()
	provider, err := oidc.NewProvider(ctx, viper.GetString("oidc.issuer"))
	if err != nil {
		// handle error
	}

	oauth2Config := oauth2.Config{
		ClientID:     viper.GetString("oidc.client_id"),
		ClientSecret: viper.GetString("oidc.client_secret"),
		//RedirectURL:  "http://localhost:8000/callback/oidc",

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}

	var verifier = provider.Verifier(&oidc.Config{ClientID: "iam-adapter"})

	return &server{
		oauth2Config: &oauth2Config,
		verifier:     verifier,
	}
}

// Serve函数用于启动服务器
func (s *server) Serve() {

	// 设置/login/oidc路径的处理函数为s.loginHandler
	http.HandleFunc("/login/oidc", s.loginHandler)
	// 设置/callback/oidc路径的处理函数为s.callbackHandler
	http.HandleFunc("/callback/oidc", s.callbackHandler)
	// 设置/路径的处理函数为s.rootHandler

	// 监听3000端口，启动服务器
	http.ListenAndServe(viper.GetString("server.listen"), nil)
}

func (s *server) loginHandler(w http.ResponseWriter, r *http.Request) {
	// @todo if logined redirect to home
	//fmt.Println(r.Header)

	state := "random"

	redirectURL := "http://localhost:3000/callback/oidc"
	if viper.GetString("server.proxyHeader") == "xforwarded" {
		xhost := r.Header.Get("X-Forwarded-Host")
		xproto := r.Header.Get("X-Forwarded-Proto")
		xport := r.Header.Get("X-Forwarded-Port")
		redirectURL = fmt.Sprintf("%s://%s:%s/%s", xproto, xhost, xport, "callback/oidc")
	}

	http.Redirect(w, r, s.oauth2Config.AuthCodeURL(state, oauth2.SetAuthURLParam("redirect_uri", redirectURL)), http.StatusFound)
}

func (s *server) callbackHandler(w http.ResponseWriter, r *http.Request) {
	// Verify state and errors.

	oauth2Token, err := s.oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		// handle error
	}

	fmt.Println(oauth2Token)
	s.token = oauth2Token

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
	http.Redirect(w, r, "/a/", http.StatusTemporaryRedirect)

}

func (s *server) rootHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r)
}

func (s *server) tokenHandler(w http.ResponseWriter, r *http.Request) {

	token2, err := s.oauth2Config.TokenSource(r.Context(), s.token).Token()
	if err != nil {
		// handle error
	}
	fmt.Println(token2)
	s.token = token2

	cookie, err := r.Cookie("Authorization")
	if err != nil {
		if err == http.ErrNoCookie {
			fmt.Println("Cookie not found")
		} else {
			fmt.Println("Error reading cookie:", err)
		}
		return
	}

	fmt.Println(cookie.Value)
}
