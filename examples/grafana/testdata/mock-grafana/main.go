// Package main is a minimal test application for graphize-appsec workflow testing.
package main

import (
	"fmt"
	"net/http"

	"github.com/plexusone/graphize-appsec/examples/grafana/testdata/mock-grafana/auth"
	"github.com/plexusone/graphize-appsec/examples/grafana/testdata/mock-grafana/datasource"
)

func main() {
	// Auth handler - simulates Grafana's auth flow
	http.HandleFunc("/login", auth.LoginHandler)
	http.HandleFunc("/oauth/callback", auth.OAuthCallback)

	// Datasource handler - simulates Grafana's datasource proxy
	http.HandleFunc("/api/datasources/proxy", datasource.ProxyHandler)

	// Dashboard API
	http.HandleFunc("/api/dashboards", handleDashboards)

	fmt.Println("Test app running on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}
}

func handleDashboards(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`{"dashboards": []}`))
}
