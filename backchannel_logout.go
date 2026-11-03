package main

import (
	"encoding/json"
	"net/http"
	"time"
)

const logoutTokenMaxAge = 5 * time.Minute
const backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// BackchannelLogout accepts OIDC Back-Channel Logout 1.0 Logout Tokens.
// It deliberately bypasses browser session loading and requires no cookies.
func (p *OAuthProxy) BackchannelLogout(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Cache-Control", "no-store")
	if req.Method != http.MethodPost {
		rw.Header().Set("Allow", http.MethodPost)
		http.Error(rw, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	verifier := p.provider.Data().LogoutVerifier
	if verifier == nil {
		http.Error(rw, "Back-channel logout is unavailable for this provider", http.StatusNotImplemented)
		return
	}
	req.Body = http.MaxBytesReader(rw, req.Body, 64<<10)
	if err := req.ParseForm(); err != nil || len(req.PostForm["logout_token"]) != 1 {
		http.Error(rw, "Invalid logout request", http.StatusBadRequest)
		return
	}
	token, err := verifier.Verify(req.Context(), req.PostForm.Get("logout_token"))
	if err != nil {
		http.Error(rw, "Invalid logout token", http.StatusBadRequest)
		return
	}
	var claims struct {
		SID       string                     `json:"sid"`
		IssuedAt  int64                      `json:"iat"`
		ExpiresAt *int64                     `json:"exp"`
		NotBefore *int64                     `json:"nbf"`
		JTI       string                     `json:"jti"`
		Nonce     json.RawMessage            `json:"nonce"`
		Events    map[string]json.RawMessage `json:"events"`
	}
	if err := token.Claims(&claims); err != nil {
		http.Error(rw, "Invalid logout claims", http.StatusBadRequest)
		return
	}
	now := time.Now()
	event, present := claims.Events[backchannelLogoutEvent]
	var eventObject map[string]json.RawMessage
	validEvent := present && json.Unmarshal(event, &eventObject) == nil && eventObject != nil && len(eventObject) == 0
	issued := time.Unix(claims.IssuedAt, 0)
	if token.Issuer == "" || (claims.SID == "" && token.Subject == "") ||
		claims.JTI == "" || claims.IssuedAt == 0 || len(claims.Nonce) != 0 || !validEvent ||
		issued.After(now.Add(time.Minute)) || now.Sub(issued) > logoutTokenMaxAge ||
		(claims.ExpiresAt != nil && now.Unix() >= *claims.ExpiresAt) ||
		(claims.NotBefore != nil && time.Unix(*claims.NotBefore, 0).After(now.Add(time.Minute))) {
		http.Error(rw, "Invalid logout claims", http.StatusBadRequest)
		return
	}
	// sid takes precedence over sub: one provider session must not log out
	// other browser sessions belonging to the same subject.
	key := logoutSelector{issuer: token.Issuer, sid: claims.SID}
	if claims.SID == "" {
		key.subject = token.Subject
	}
	if !p.sessionTracker.revoke(key, claims.IssuedAt, p.CookieOptions.Expire, token.Issuer+"\x00"+claims.JTI) {
		http.Error(rw, "Logout token already used", http.StatusBadRequest)
		return
	}
	rw.WriteHeader(http.StatusOK)
}
