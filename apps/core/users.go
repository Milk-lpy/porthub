package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"porthub/internal/auth"
	"strconv"
)

type userView struct {
	ID         int    `json:"id"`
	Username   string `json:"username"`
	Role       string `json:"role"`
	MustChange bool   `json:"must_change"`
}

func users(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, listUsers())
	case http.MethodPost:
		createUser(w, r)
	case http.MethodPut:
		updateUser(w, r)
	case http.MethodDelete:
		deleteUser(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func createUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateUsername(req.Username); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Role == "" {
		req.Role = "readonly"
	}
	if err := validateRole(req.Role); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	password := req.Password
	if password == "" {
		password = auth.RandomPassword()
	}
	if err := auth.ValidatePassword(password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hash, _ := auth.HashPassword(password)
	secret := auth.NewTOTPSecret()
	res, err := db.Exec("insert into users(username,passhash,totp,role,must_change) values(?,?,?,?,1)", req.Username, hash, secret, req.Role)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id, _ := res.LastInsertId()
	audit(actor(r), "user_create", req.Username)
	writeJSON(w, map[string]any{"id": id, "username": req.Username, "role": req.Role, "initial_password": password, "totp_secret": secret})
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID         int    `json:"id"`
		Username   string `json:"username"`
		Role       string `json:"role"`
		MustChange bool   `json:"must_change"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.ID < 1 {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	if err := validateUsername(req.Username); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateRole(req.Role); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := ensureSuperAdminNotRemoved(req.ID, req.Role); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, err := db.Exec("update users set username=?,role=?,must_change=? where id=?", req.Username, req.Role, boolInt(req.MustChange), req.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit(actor(r), "user_update", strconv.Itoa(req.ID))
	writeJSON(w, map[string]any{"ok": true})
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil || id < 1 {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	var username, role string
	if err := db.QueryRow("select username,role from users where id=?", id).Scan(&username, &role); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if username == actor(r) {
		http.Error(w, "cannot delete current user", http.StatusBadRequest)
		return
	}
	if err := ensureSuperAdminNotRemoved(id, "deleted"); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	db.Exec("delete from sessions where username=?", username)
	db.Exec("delete from users where id=?", id)
	audit(actor(r), "user_delete", strconv.Itoa(id))
	writeJSON(w, map[string]any{"ok": true})
}

func userResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID       int    `json:"id"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.ID < 1 {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	password := req.Password
	if password == "" {
		password = auth.RandomPassword()
	}
	if err := auth.ValidatePassword(password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hash, _ := auth.HashPassword(password)
	res, err := db.Exec("update users set passhash=?,must_change=1 where id=?", hash, req.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	db.Exec("update trusted_devices set revoked=1 where username=(select username from users where id=?)", req.ID)
	audit(actor(r), "user_password_reset", strconv.Itoa(req.ID))
	writeJSON(w, map[string]any{"ok": true, "temporary_password": password})
}

func userResetTOTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.ID < 1 {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	secret := auth.NewTOTPSecret()
	res, err := db.Exec("update users set totp=?,must_change=1 where id=?", secret, req.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	db.Exec("update trusted_devices set revoked=1 where username=(select username from users where id=?)", req.ID)
	// Revoke all existing sessions for the user whose TOTP was reset.
	db.Exec("delete from sessions where username=(select username from users where id=?)", req.ID)
	audit(actor(r), "user_totp_reset", strconv.Itoa(req.ID))
	writeJSON(w, map[string]any{"ok": true, "totp_secret": secret})
}

func listUsers() []userView {
	rows, _ := db.Query("select id,username,role,must_change from users order by id")
	defer rows.Close()
	var out []userView
	for rows.Next() {
		var u userView
		var must int
		rows.Scan(&u.ID, &u.Username, &u.Role, &must)
		u.MustChange = must == 1
		out = append(out, u)
	}
	return out
}

func validateUsername(value string) error {
	if len(value) < 3 || len(value) > 64 {
		return errors.New("username length must be 3-64")
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			continue
		}
		return errors.New("username contains invalid character")
	}
	return nil
}

func validateRole(role string) error {
	switch role {
	case "super_admin", "admin", "operator", "readonly":
		return nil
	default:
		return errors.New("invalid role")
	}
}

func ensureSuperAdminNotRemoved(id int, nextRole string) error {
	var currentRole string
	err := db.QueryRow("select role from users where id=?", id).Scan(&currentRole)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("not found")
	}
	if err != nil {
		return err
	}
	if currentRole != "super_admin" || nextRole == "super_admin" {
		return nil
	}
	var n int
	db.QueryRow("select count(*) from users where role='super_admin' and id<>?", id).Scan(&n)
	if n == 0 {
		return errors.New("at least one super_admin is required")
	}
	return nil
}
