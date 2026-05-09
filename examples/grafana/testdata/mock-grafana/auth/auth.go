// Package auth simulates Grafana's authentication module.
package auth

import (
	"net/http"
	"strings"
)

// LoginHandler handles user login requests.
// CVE-2023-6152: Email validation bypass vulnerability
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	password := r.FormValue("password")

	// Vulnerable: insufficient email validation
	if !ValidateEmail(email) {
		http.Error(w, "Invalid email", http.StatusBadRequest)
		return
	}

	if !CheckCredentials(email, password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	w.Write([]byte(`{"status": "logged_in"}`))
}

// OAuthCallback handles OAuth provider callbacks.
// CVE-2023-3128: Azure AD account takeover via email claim
func OAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// Exchange code for token
	token, err := ExchangeOAuthCode(code, state)
	if err != nil {
		http.Error(w, "OAuth error", http.StatusBadRequest)
		return
	}

	// Vulnerable: trusting email claim without verification
	email := token.Claims["email"].(string)
	user := LookupUserByEmail(email)

	if user == nil {
		// Auto-create user from OAuth (potential takeover)
		user = CreateUserFromOAuth(token)
	}

	w.Write([]byte(`{"user": "` + user.Name + `"}`))
}

// ValidateEmail performs basic email validation.
// Vulnerable to bypass with specially crafted addresses
func ValidateEmail(email string) bool {
	return strings.Contains(email, "@")
}

// CheckCredentials verifies user credentials.
func CheckCredentials(email, password string) bool {
	// Placeholder
	return password != ""
}

// OAuthToken represents an OAuth token response.
type OAuthToken struct {
	AccessToken string
	Claims      map[string]any
}

// ExchangeOAuthCode exchanges an authorization code for a token.
func ExchangeOAuthCode(code, state string) (*OAuthToken, error) {
	// Placeholder - would call OAuth provider
	return &OAuthToken{
		AccessToken: "token",
		Claims:      map[string]any{"email": "user@example.com"},
	}, nil
}

// User represents a user account.
type User struct {
	ID    int
	Name  string
	Email string
}

// LookupUserByEmail finds a user by email address.
func LookupUserByEmail(email string) *User {
	// Placeholder
	return nil
}

// CreateUserFromOAuth creates a new user from OAuth claims.
func CreateUserFromOAuth(token *OAuthToken) *User {
	return &User{
		Name:  "New User",
		Email: token.Claims["email"].(string),
	}
}
