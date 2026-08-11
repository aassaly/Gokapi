package oauth

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/webserver/authentication"
	"github.com/forceu/gokapi/internal/webserver/errorHandling"
	"golang.org/x/oauth2"
)

var config oauth2.Config
var ctx context.Context
var provider *oidc.Provider

// Init starts the oauth connection
func Init(baseUrl string, credentials models.AuthenticationConfig) {
	var err error
	ctx = context.Background()
	provider, err = oidc.NewProvider(ctx, credentials.OAuthProvider)
	if err != nil {
		log.Fatal(err)
	}

	systemConfig := configuration.Get()
	scopes := []string{oidc.ScopeOpenID, "profile", "email"}
	if systemConfig.Authentication.OAuthGroupScope != "" {
		scopes = append(scopes, systemConfig.Authentication.OAuthGroupScope)
	}

	config = oauth2.Config{
		ClientID:     credentials.OAuthClientId,
		ClientSecret: credentials.OAuthClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  baseUrl + "oauth-callback",
		Scopes:       scopes,
	}
}

const (
	promptSilent = iota
	promptSelectAccount
	promptConsent
)

// HandlerLogin is a handler for showing the login screen
func HandlerLogin(w http.ResponseWriter, r *http.Request) {
	// If user clicked logout, force account selection
	if r.URL.Query().Has("consent") {
		initLogin(w, r, promptConsent)
		return
	}
	initLogin(w, r, promptSilent)
}

func initLogin(w http.ResponseWriter, r *http.Request, screenType int) {
	state := helper.GenerateRandomString(32)
	nonce := helper.GenerateRandomString(32)
	verifier := oauth2.GenerateVerifier()
	setCallbackCookie(w, state)
	setNamedCallbackCookie(w, authentication.CookieOauthNonce, nonce)
	setNamedCallbackCookie(w, authentication.CookieOauthVerifier, verifier)
	var prompt string
	switch screenType {
	case promptSilent:
		prompt = "none"
	case promptSelectAccount:
		prompt = "select_account"
	case promptConsent:
		prompt = "consent"
	default:
		panic("invalid screen type")
	}
	http.Redirect(w, r, config.AuthCodeURL(state,
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("prompt", prompt)), http.StatusFound)
}

func isConsentRequired(r *http.Request) bool {
	return r.URL.Query().Get("error") == "consent_required"
}

func isLoginRequired(r *http.Request) bool {
	errorCode := r.URL.Query().Get("error")
	return errorCode == "login_required" || errorCode == "interaction_required"
}

// HandlerCallback is a handler for processing the oauth callback
func HandlerCallback(w http.ResponseWriter, r *http.Request) {
	state, err := readCallbackCookie(r, authentication.CookieOauth)
	if err != nil {
		errorHandling.RedirectToOAuthErrorPage(w, r, "Parameter state was not provided", err)
		return
	}
	if r.URL.Query().Get("state") != state {
		errorHandling.RedirectToOAuthErrorPage(w, r, "Parameter state did not match", err)
		return
	}

	if isConsentRequired(r) {
		initLogin(w, r, promptConsent)
		return
	}
	if isLoginRequired(r) {
		initLogin(w, r, promptSelectAccount)
		return
	}
	nonce, err := readCallbackCookie(r, authentication.CookieOauthNonce)
	if err != nil {
		errorHandling.RedirectToOAuthErrorPage(w, r, "OIDC nonce was not provided", err)
		return
	}
	verifier, err := readCallbackCookie(r, authentication.CookieOauthVerifier)
	if err != nil {
		errorHandling.RedirectToOAuthErrorPage(w, r, "PKCE verifier was not provided", err)
		return
	}
	clearCallbackCookies(w)

	oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		errorHandling.RedirectToOAuthErrorPage(w, r, "Failed to exchange token", err)
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		errorHandling.RedirectToOAuthErrorPage(w, r, "OIDC provider did not return an ID token", nil)
		return
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: config.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		errorHandling.RedirectToOAuthErrorPage(w, r, "Failed to verify ID token", err)
		return
	}
	var idClaims struct {
		Nonce string `json:"nonce"`
	}
	if err := idToken.Claims(&idClaims); err != nil || idClaims.Nonce != nonce {
		errorHandling.RedirectToOAuthErrorPage(w, r, "OIDC nonce did not match", err)
		return
	}

	userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
	if err != nil {
		errorHandling.RedirectToOAuthErrorPage(w, r, "Failed to get user info", err)
		return
	}
	if userInfo.Email == "" {
		errorHandling.RedirectToOAuthErrorPage(w, r, "An empty email address was provided.\nPlease make sure that you have your"+
			" email address set in your authentication user backend.", nil)
		return
	}
	info := authentication.OAuthUserInfo{
		Subject:    userInfo.Subject,
		Email:      userInfo.Email,
		ClaimsSent: userInfo,
	}
	err = authentication.CheckOauthUserAndRedirect(w, r, info)
	if err != nil {
		errorHandling.RedirectToOAuthErrorPage(w, r, "Failed to continue with login: ", err)
	}
}

func setCallbackCookie(w http.ResponseWriter, value string) {
	setNamedCallbackCookie(w, authentication.CookieOauth, value)
}

func setNamedCallbackCookie(w http.ResponseWriter, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/oauth-callback",
		MaxAge:   int((10 * time.Minute).Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, c)
}

func readCallbackCookie(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil || cookie.Value == "" {
		return "", errors.New("OIDC callback cookie is missing")
	}
	return cookie.Value, nil
}

func clearCallbackCookies(w http.ResponseWriter) {
	for _, name := range []string{authentication.CookieOauth, authentication.CookieOauthNonce, authentication.CookieOauthVerifier} {
		http.SetCookie(w, &http.Cookie{Name: name, Path: "/oauth-callback", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	}
}
