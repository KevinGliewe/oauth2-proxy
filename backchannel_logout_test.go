package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/justinas/alice"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	internal "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/oidc"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
	"golang.org/x/net/websocket"
)

func logoutTestSession(sid, sub string, issued int64) *sessionsapi.SessionState {
	payload, _ := json.Marshal(map[string]interface{}{"iss": "https://issuer.example", "sid": sid, "sub": sub, "iat": issued})
	expiry := time.Now().Add(time.Hour)
	return &sessionsapi.SessionState{IDToken: "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature", ExpiresOn: &expiry}
}

func TestSessionTrackerIsolationAndRegistrationRace(t *testing.T) {
	var tracker sessionTracker
	a := logoutTestSession("a", "user", time.Now().Unix()-60)
	b := logoutTestSession("b", "user", time.Now().Unix()-60)
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	removeA, _ := tracker.register(a, cancelA)
	defer removeA()
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	removeB, _ := tracker.register(b, cancelB)
	defer removeB()
	tracker.revoke(logoutSelector{issuer: "https://issuer.example", sid: "a"}, time.Now().Unix(), time.Hour, "")
	if ctxA.Err() == nil || ctxB.Err() != nil {
		t.Fatal("logout must close only the matching provider session")
	}
	if _, ok := tracker.register(a, func() {}); ok {
		t.Fatal("revoked session registered")
	}
	tracker.revoke(logoutSelector{issuer: "https://issuer.example", subject: "user"}, time.Now().Unix(), time.Hour, "")
	if ctxB.Err() == nil {
		t.Fatal("subject logout did not close other session")
	}
	fresh := logoutTestSession("new", "user", time.Now().Unix()+2)
	if tracker.revoked(fresh) {
		t.Fatal("new login revoked by older subject logout")
	}
	other := logoutTestSession("a", "other", time.Now().Unix())
	// A logout racing an upgrade must either cancel its registration or deny it.
	for i := 0; i < 100; i++ {
		var tr sessionTracker
		ctx, cancel := context.WithCancel(context.Background())
		var remove func()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			var ok bool
			remove, ok = tr.register(other, cancel)
			if !ok {
				cancel()
			}
		}()
		go func() { defer wg.Done(); tr.logoutSession(other, time.Hour) }()
		wg.Wait()
		if ctx.Err() == nil {
			t.Fatal("logout missed concurrent upgrade")
		}
		if remove != nil {
			remove()
		}
		cancel()
	}

}

func TestWebSocketsCloseOnLogout(t *testing.T) {
	upstream := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		defer ws.Close()
		for {
			var msg string
			if websocket.Message.Receive(ws, &msg) != nil {
				return
			}
			if websocket.Message.Send(ws, msg) != nil {
				return
			}
		}
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	p := &OAuthProxy{headersChain: alice.New(), upstreamProxy: httputil.NewSingleHostReverseProxy(target)}
	a := logoutTestSession("a", "user", time.Now().Unix()-60)
	b := logoutTestSession("b", "user", time.Now().Unix()-60)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := a
		if r.URL.Path == "/b" {
			session = b
		}
		p.proxyWithSession(w, r, session)
	}))
	defer server.Close()
	dial := func(path string) *websocket.Conn {
		ws, err := websocket.Dial("ws"+strings.TrimPrefix(server.URL, "http")+path, "", server.URL)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ws.Close() })
		return ws
	}
	wsA, wsA2, wsB := dial("/a"), dial("/a"), dial("/b")
	assertEcho := func(ws *websocket.Conn) {
		t.Helper()
		_ = ws.SetDeadline(time.Now().Add(3 * time.Second))
		if err := websocket.Message.Send(ws, "hello"); err != nil {
			t.Fatal(err)
		}
		var msg string
		if err := websocket.Message.Receive(ws, &msg); err != nil || msg != "hello" {
			t.Fatalf("echo: %q %v", msg, err)
		}
	}
	assertEcho(wsA)
	assertEcho(wsA2)
	assertEcho(wsB)
	p.sessionTracker.revoke(logoutSelector{issuer: "https://issuer.example", sid: "a"}, time.Now().Unix(), time.Hour, "")
	for _, ws := range []*websocket.Conn{wsA, wsA2} {
		_ = ws.SetReadDeadline(time.Now().Add(3 * time.Second))
		var msg string
		if err := websocket.Message.Receive(ws, &msg); err == nil {
			t.Fatal("logged-out socket still open")
		} else if e, ok := err.(net.Error); ok && e.Timeout() {
			t.Fatal("socket timed out instead of closing")
		}
	}
	assertEcho(wsB)
	if ws, err := websocket.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/a", "", server.URL); err == nil {
		ws.Close()
		t.Fatal("revoked session reconnected")
	}
	p.sessionTracker.logoutSession(b, time.Hour)
	_ = wsB.SetReadDeadline(time.Now().Add(3 * time.Second))
	var msg string
	if err := websocket.Message.Receive(wsB, &msg); err == nil {
		t.Fatal("local logout left socket open")
	}
}

func TestBackchannelLogoutTokens(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, Algorithm: "RS256", Use: "sig"}}})
	}))
	defer jwks.Close()
	pv, err := internal.NewProviderVerifier(context.Background(), internal.ProviderVerifierOptions{
		IssuerURL: "https://issuer.example", ClientID: "client",
		JWKsURL: jwks.URL, SkipDiscovery: true, AudienceClaims: []string{"aud"},
		SkipIssuerVerification: true, ExtraAudiences: []string{"other"},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier := pv.LogoutVerifier()
	p := &OAuthProxy{
		CookieOptions: &options.Cookie{Expire: time.Hour},
		provider:      &providers.OIDCProvider{ProviderData: &providers.ProviderData{LogoutVerifier: verifier}},
	}
	claims := func() map[string]interface{} {
		return map[string]interface{}{"iss": "https://issuer.example", "aud": "client", "sub": "user", "sid": "a", "iat": time.Now().Unix(), "jti": "unique", "events": map[string]interface{}{backchannelLogoutEvent: map[string]interface{}{}}}
	}
	sign := func(c map[string]interface{}) string {
		b, _ := json.Marshal(c)
		obj, err := signer.Sign(b)
		if err != nil {
			t.Fatal(err)
		}
		token, err := obj.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	sendForm := func(target string, form url.Values) int {
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		p.BackchannelLogout(w, req)
		return w.Code
	}
	send := func(token string) int {
		return sendForm("/oauth2/backchannel_logout", url.Values{"logout_token": {token}})
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/backchannel_logout", nil)
	methodResponse := httptest.NewRecorder()
	p.BackchannelLogout(methodResponse, req)
	if methodResponse.Code != http.StatusMethodNotAllowed {
		t.Fatal("GET must be rejected")
	}

	for _, tc := range []struct {
		name   string
		change func(map[string]interface{})
	}{
		{"issuer", func(c map[string]interface{}) { c["iss"] = "https://evil.example" }},
		{"audience", func(c map[string]interface{}) { c["aud"] = "other" }},
		{"nonce", func(c map[string]interface{}) { c["nonce"] = nil }},
		{"event", func(c map[string]interface{}) { delete(c, "events") }},
		{"null event", func(c map[string]interface{}) { c["events"] = map[string]interface{}{backchannelLogoutEvent: nil} }},
		{"identifier", func(c map[string]interface{}) { delete(c, "sid"); delete(c, "sub") }},
		{"jti", func(c map[string]interface{}) { delete(c, "jti") }},
		{"stale", func(c map[string]interface{}) { c["iat"] = time.Now().Add(-10 * time.Minute).Unix() }},
		{"future", func(c map[string]interface{}) { c["iat"] = time.Now().Add(10 * time.Minute).Unix() }},
		{"expired", func(c map[string]interface{}) { c["exp"] = time.Now().Add(-time.Minute).Unix() }},
		{"not yet valid", func(c map[string]interface{}) { c["nbf"] = time.Now().Add(10 * time.Minute).Unix() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := claims()
			tc.change(c)
			if status := send(sign(c)); status != 400 {
				t.Fatalf("status %d", status)
			}
		})
	}
	if status := send("unsigned"); status != 400 {
		t.Fatalf("unsigned status %d", status)
	}
	// A structurally valid token signed by a different key must fail verification.
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: otherKey}, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims())
	if err != nil {
		t.Fatal(err)
	}
	wrongSignature, err := otherSigner.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	wrongToken, err := wrongSignature.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	if status := send(wrongToken); status != http.StatusBadRequest {
		t.Fatalf("wrong signature status %d", status)
	}

	for _, tc := range []struct {
		name, target string
		form         url.Values
	}{
		{"query only", "/oauth2/backchannel_logout?logout_token=" + url.QueryEscape(sign(claims())), nil},
		{"duplicate body", "/oauth2/backchannel_logout", url.Values{"logout_token": {sign(claims()), sign(claims())}}},
		{"oversized body", "/oauth2/backchannel_logout", url.Values{"logout_token": {strings.Repeat("x", 64<<10)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if status := sendForm(tc.target, tc.form); status != http.StatusBadRequest {
				t.Fatalf("status %d", status)
			}
		})
	}
	withQuery := claims()
	withQuery["jti"] = "body-not-query"
	withQuery["nbf"] = time.Now().Add(-time.Minute).Unix()
	if status := sendForm("/oauth2/backchannel_logout?logout_token=invalid&logout_token=also-invalid", url.Values{"logout_token": {sign(withQuery)}}); status != http.StatusOK {
		t.Fatalf("valid body with ignored query status %d", status)
	}

	token := sign(claims()) // exp is optional in Logout Tokens
	if status := send(token); status != 200 {
		t.Fatalf("valid status %d", status)
	}
	if !p.sessionTracker.revoked(logoutTestSession("a", "user", time.Now().Unix()-60)) {
		t.Fatal("logout did not revoke session")
	}
	if p.sessionTracker.revoked(logoutTestSession("b", "user", time.Now().Unix()-60)) {
		t.Fatal("sid logout revoked a different session")
	}
	if status := send(token); status != 400 {
		t.Fatalf("replay status %d", status)
	}
	c := claims()
	delete(c, "sid")
	c["jti"] = "subject"
	if status := send(sign(c)); status != 200 {
		t.Fatalf("subject status %d", status)
	}
	if !p.sessionTracker.revoked(logoutTestSession("b", "user", time.Now().Unix()-60)) {
		t.Fatal("subject logout did not revoke all sessions")
	}
}

func TestSignOutCancelsSessionConnections(t *testing.T) {
	opts := baseTestOptions()
	if err := validation.Validate(opts); err != nil {
		t.Fatal(err)
	}
	p, err := NewOAuthProxy(opts, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	session := &sessionsapi.SessionState{Email: "user@example.com", IDToken: "test-id-token"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	remove, ok := p.sessionTracker.register(session, cancel)
	if !ok {
		t.Fatal("session registration failed")
	}
	defer remove()
	save := httptest.NewRecorder()
	if err := p.sessionStore.Save(save, httptest.NewRequest("GET", "/", nil), session); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/oauth2/sign_out", nil)
	req.Header.Set("Cookie", save.Header().Get("Set-Cookie"))
	response := httptest.NewRecorder()
	p.ServeHTTP(response, req)
	if response.Code != http.StatusFound || ctx.Err() != context.Canceled {
		t.Fatalf("sign-out status %d; connection context %v", response.Code, ctx.Err())
	}
}
