package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/justinas/alice"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"golang.org/x/net/websocket"
	"testing"
	"time"

	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

func TestSessionTrackerSessionCookieLogoutDoesNotExpire(t *testing.T) {
	for _, kind := range []string{"browser", "sid", "subject"} {
		t.Run(kind, func(t *testing.T) {
			var tracker sessionTracker
			session := logoutTestSession("browser-id", "subject", 100)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			remove, ok := tracker.register(session, cancel)
			if !ok {
				t.Fatal("new session rejected")
			}
			defer remove()
			switch kind {
			case "browser":
				tracker.logoutSession(session, 0)
			case "sid":
				tracker.revoke(logoutSelector{issuer: "https://issuer.example", sid: "browser-id"}, 200, 0, "")
			case "subject":
				tracker.revoke(logoutSelector{issuer: "https://issuer.example", subject: "subject"}, 200, 0, "")
			}
			if ctx.Err() != context.Canceled {
				t.Fatal("logout left existing connection open")
			}
			// Session cookies have no server-side age limit. A subsequent
			// request, including after ordinary record collection, must not
			// authenticate a previously logged-out cookie.
			tracker.prune(time.Now().Add(365 * 24 * time.Hour))
			if !tracker.revoked(session) {
				t.Fatal("session cookie's revocation was discarded")
			}
			if remove, ok := tracker.register(session, func() {}); ok {
				remove()
				t.Fatal("logged-out session cookie reconnected")
			}
		})
	}
}

func TestSessionTrackerBasicLogoutAllowsFreshCredentials(t *testing.T) {
	var tracker sessionTracker
	old := &sessionsapi.SessionState{User: "basic-user"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	remove, ok := tracker.register(old, cancel)
	if !ok {
		t.Fatal("initial authentication rejected")
	}
	defer remove()
	tracker.logoutSession(old, 168*time.Hour)
	if ctx.Err() != context.Canceled {
		t.Fatal("logout left existing Basic-auth connection open")
	}
	fresh := &sessionsapi.SessionState{User: "basic-user"}
	if tracker.revoked(fresh) {
		t.Fatal("logout blacklisted fresh Basic credentials")
	}
	freshCtx, freshCancel := context.WithCancel(context.Background())
	defer freshCancel()
	freshRemove, ok := tracker.register(fresh, freshCancel)
	if !ok || freshCtx.Err() != nil {
		t.Fatal("fresh Basic credentials cannot reconnect")
	}
	defer freshRemove()
}

func TestSessionTrackerMatchesPersistedOIDCIdentity(t *testing.T) {
	for _, kind := range []string{"sid", "subject"} {
		t.Run(kind, func(t *testing.T) {
			var tracker sessionTracker
			// Minimal cookie sessions omit IDToken, but must retain matching
			// information for both per-session and per-subject logout.
			session := &sessionsapi.SessionState{
				OIDCSession: &sessionsapi.OIDCSessionState{
					Issuer: "https://issuer.example", Subject: "subject",
					SID: "browser-id", IssuedAt: 100,
				},
				Nonce: []byte("per-login-nonce"),
			}
			key := logoutSelector{issuer: "https://issuer.example", sid: "browser-id"}
			if kind == "subject" {
				key.sid = ""
				key.subject = "subject"
			}
			tracker.revoke(key, 200, time.Hour, "")
			if !tracker.revoked(session) {
				t.Fatal("minimal-cookie identity was not revoked")
			}
			// Token refresh must not replace the preserved issuance time
			// when matching an earlier subject logout.
			session.IDToken = logoutTestSession("browser-id", "subject", 300).IDToken
			if !tracker.revoked(session) {
				t.Fatal("replacement token bypassed original session revocation")
			}
		})
	}
}

func TestSessionTrackerExpiredRevocationDoesNotWaitForCollection(t *testing.T) {
	session := logoutTestSession("browser-id", "subject", 100)
	id := identityFromSession(session)
	for _, key := range []logoutSelector{
		{local: id.Local},
		{issuer: id.Issuer, sid: id.SID},
		{issuer: id.Issuer, subject: id.Subject},
	} {
		tracker := sessionTracker{
			nextPrune: time.Now().Add(time.Hour),
			revocations: map[logoutSelector]revocation{
				key: {until: time.Now().Add(-time.Second), issuedAt: 200},
			},
		}
		if tracker.revoked(session) {
			t.Fatal("expired revocation blocked authentication until periodic collection")
		}
		remove, ok := tracker.register(session, func() {})
		if !ok {
			t.Fatal("expired revocation blocked a new connection")
		}
		remove()
	}
}

func TestWebSocketClosesAtCookieExpiryWithoutTokenExpiry(t *testing.T) {
	upstream := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		defer ws.Close()
		for {
			var message string
			if websocket.Message.Receive(ws, &message) != nil {
				return
			}
			if websocket.Message.Send(ws, message) != nil {
				return
			}
		}
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	proxy := &OAuthProxy{
		CookieOptions: &options.Cookie{Expire: 500 * time.Millisecond},
		headersChain:  alice.New(), upstreamProxy: httputil.NewSingleHostReverseProxy(target),
	}
	created := time.Now()
	session := &sessionsapi.SessionState{
		User: "browser-user", Nonce: []byte("per-browser-login"), CreatedAt: &created,
		// A provider may issue no token expiration at all. Cookie expiry
		// still bounds the authorization held by an open WebSocket.
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.proxyWithSession(w, r, session)
	}))
	defer server.Close()
	ws, err := websocket.Dial("ws"+strings.TrimPrefix(server.URL, "http"), "", server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	_ = ws.SetDeadline(time.Now().Add(3 * time.Second))
	if err := websocket.Message.Send(ws, "connected"); err != nil {
		t.Fatal(err)
	}
	var message string
	if err := websocket.Message.Receive(ws, &message); err != nil || message != "connected" {
		t.Fatalf("initial echo: %q %v", message, err)
	}
	if err := websocket.Message.Receive(ws, &message); err == nil {
		t.Fatal("socket remained open after its cookie expired")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("socket timed out instead of closing at cookie expiry")
	}
}
