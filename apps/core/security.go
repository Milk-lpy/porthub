package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"porthub/internal/auth"
	"strings"
	"time"
)

type ctxKey string

const actorKey ctxKey = "actor"
const roleKey ctxKey = "role"
const trustedDeviceCookie = "ph_trusted_device"
const trustedDeviceTTL = 30 * 24 * time.Hour

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var x struct {
		Username       string
		Password       string
		TOTP           string
		RememberDevice bool
	}
	json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&x)
	limitKey := loginLimitKey(r, x.Username)
	if retryAfter, limited := loginRetryAfter(limitKey); limited {
		audit("anonymous", "login_rate_limited", x.Username)
		writeRateLimited(w, retryAfter)
		return
	}
	var h, sec, role string
	var mc int
	err := db.QueryRow("select passhash,totp,role,must_change from users where username=?", x.Username).Scan(&h, &sec, &role, &mc)
	// Always run CheckPassword to avoid username-enumeration via timing.
	// For unknown users, h is empty and CheckPassword will return false.
	passwordOK := auth.CheckPassword(x.Password, h) && err == nil
	var totpCounter int64
	var totpValid bool
	if passwordOK && x.TOTP != "" {
		totpCounter, totpValid = auth.VerifyTOTP(sec, x.TOTP)
		if totpValid {
			// Enforce replay protection: only accept if counter is strictly greater
			// than the last accepted counter stored for this user.
			var lastCounter int64
			db.QueryRow("select coalesce(totp_last_counter,-1) from users where username=?", x.Username).Scan(&lastCounter)
			if totpCounter <= lastCounter {
				totpValid = false // replay detected
			} else {
				db.Exec("update users set totp_last_counter=? where username=?", totpCounter, x.Username)
			}
		}
	}
	totpOK := totpValid
	trustedOK := passwordOK && trustedDeviceValid(r, x.Username)
	if !passwordOK || (!totpOK && !trustedOK) {
		recordLoginFailure(limitKey)
		audit("anonymous", "login_failed", x.Username)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	clearLoginFailures(limitKey)
	sid := auth.RandomPassword()
	csrf := auth.RandomPassword()
	expires := time.Now().Add(12 * time.Hour).Unix()
	db.Exec("insert or replace into sessions(id,username,csrf,expires_at) values(?,?,?,?)", sid, x.Username, csrf, expires)
	http.SetCookie(w, &http.Cookie{Name: "ph_session", Value: sid, Path: "/", MaxAge: int((12 * time.Hour).Seconds()), Expires: time.Unix(expires, 0), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	if totpOK && x.RememberDevice {
		setTrustedDevice(w, r, x.Username)
	}
	audit(x.Username, "login", "")
	writeJSON(w, map[string]any{"ok": true, "username": x.Username, "role": role, "csrf": csrf, "must_change": mc == 1, "trusted_device": trustedOK})
}

func sessionStatus(w http.ResponseWriter, r *http.Request) {
	user := actor(r)
	var role, csrf string
	var mustChange int
	cookie, err := r.Cookie("ph_session")
	if err != nil || strings.HasPrefix(user, "api_token:") {
		http.Error(w, "browser session required", http.StatusBadRequest)
		return
	}
	err = db.QueryRow("select u.role,u.must_change,s.csrf from sessions s join users u on u.username=s.username where s.id=?", cookie.Value).Scan(&role, &mustChange, &csrf)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "username": user, "role": role, "csrf": csrf, "must_change": mustChange == 1})
}

func logout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("ph_session")
	if err == nil {
		db.Exec("delete from sessions where id=?", c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "ph_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, map[string]any{"ok": true})
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if raw := bearerToken(r); raw != "" {
			tokenActor, role, ok := authenticateAPIToken(raw)
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if !roleAllowed(role, r.Method, r.URL.Path) {
				http.Error(w, "forbidden for token role", http.StatusForbidden)
				return
			}
			ctx := context.WithValue(r.Context(), actorKey, tokenActor)
			ctx = context.WithValue(ctx, roleKey, role)
			next(w, r.WithContext(ctx))
			return
		}
		c, err := r.Cookie("ph_session")
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var username, csrf string
		var expires int64
		err = db.QueryRow("select username,csrf,expires_at from sessions where id=?", c.Value).Scan(&username, &csrf, &expires)
		if err != nil || expires < time.Now().Unix() {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		role := userRole(username)
		if !roleAllowed(role, r.Method, r.URL.Path) {
			http.Error(w, "forbidden for user role", http.StatusForbidden)
			return
		}
		// Enforce must_change on the server: a user with a temporary password
		// may only change their password (and log out) until they comply.
		var mustChange int
		db.QueryRow("select must_change from users where username=?", username).Scan(&mustChange)
		if mustChange == 1 && r.URL.Path != "/api/password/change" && r.URL.Path != "/api/logout" {
			http.Error(w, "password change required", http.StatusForbidden)
			return
		}
		if mutates(r.Method) && subtle.ConstantTimeCompare([]byte(csrf), []byte(r.Header.Get("X-CSRF-Token"))) != 1 {
			http.Error(w, "csrf required", http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), actorKey, username)
		ctx = context.WithValue(ctx, roleKey, role)
		next(w, r.WithContext(ctx))
	}
}

func userRole(username string) string {
	var role string
	if err := db.QueryRow("select role from users where username=?", username).Scan(&role); err != nil || role == "" {
		return "readonly"
	}
	return role
}

func authenticateAPIToken(raw string) (string, string, bool) {
	if raw == "" {
		return "", "", false
	}
	var prefix, role string
	err := db.QueryRow("select prefix,role from api_tokens where token_hash=? and revoked=0", hashToken(raw)).Scan(&prefix, &role)
	if err != nil {
		return "", "", false
	}
	db.Exec("update api_tokens set last_used_at=? where token_hash=?", time.Now().Format(time.RFC3339), hashToken(raw))
	return "api_token:" + prefix, role, true
}

func changePassword(w http.ResponseWriter, r *http.Request) {
	var x struct{ OldPassword, NewPassword, TOTP string }
	json.NewDecoder(r.Body).Decode(&x)
	if err := auth.ValidatePassword(x.NewPassword); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	user := actor(r)
	var h, sec string
	if err := db.QueryRow("select passhash,totp from users where username=?", user).Scan(&h, &sec); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	_, totpOK := auth.VerifyTOTP(sec, x.TOTP)
	if !auth.CheckPassword(x.OldPassword, h) || !totpOK {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	nht, _ := auth.HashPassword(x.NewPassword)
	db.Exec("update users set passhash=?,must_change=0 where username=?", nht, user)
	// Revoke every other session for this user (password change invalidates
	// all previously issued sessions except the current one).
	db.Exec("delete from sessions where username=? and id<>?", user, currentSessionID(r))
	db.Exec("update trusted_devices set revoked=1 where username=?", user)
	// Destroy the bootstrap credential file now that the admin has a real
	// password: the plaintext initial password + TOTP secret must not linger.
	os.Remove(filepath.Join(dataDir, "initial-admin.txt"))
	audit(user, "password_change", "")
	writeJSON(w, map[string]any{"ok": true})
}

func trustedDeviceValid(r *http.Request, username string) bool {
	c, err := r.Cookie(trustedDeviceCookie)
	if err != nil || c.Value == "" {
		return false
	}
	var expires int64
	err = db.QueryRow("select expires_at from trusted_devices where username=? and token_hash=? and revoked=0", username, hashToken(c.Value)).Scan(&expires)
	if err != nil || expires < time.Now().Unix() {
		return false
	}
	db.Exec("update trusted_devices set last_used_at=? where token_hash=?", time.Now().Format(time.RFC3339), hashToken(c.Value))
	return true
}

func setTrustedDevice(w http.ResponseWriter, r *http.Request, username string) {
	raw := auth.RandomPassword()
	now := time.Now()
	expires := now.Add(trustedDeviceTTL)
	db.Exec("insert into trusted_devices(username,token_hash,user_agent,created_at,expires_at,revoked) values(?,?,?,?,?,0)", username, hashToken(raw), r.UserAgent(), now.Format(time.RFC3339), expires.Unix())
	http.SetCookie(w, &http.Cookie{Name: trustedDeviceCookie, Value: raw, Path: "/", MaxAge: int(trustedDeviceTTL.Seconds()), Expires: expires, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func actor(r *http.Request) string {
	if v, ok := r.Context().Value(actorKey).(string); ok && v != "" {
		return v
	}
	return "system"
}

// currentSessionID returns the ph_session cookie value of the request, used to
// keep the current session alive when revoking all other sessions.
func currentSessionID(r *http.Request) string {
	if c, err := r.Cookie("ph_session"); err == nil {
		return c.Value
	}
	return ""
}

func audit(actor, action, detail string) {
	ts := time.Now().Format(time.RFC3339)
	db.Exec("insert into audit values(?,?,?,?)", ts, actor, action, detail)
	dispatchWebhookEvent(actor, action, detail, ts)
}

func mutates(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}
