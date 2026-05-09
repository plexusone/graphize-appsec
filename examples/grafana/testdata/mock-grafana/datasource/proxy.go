// Package datasource simulates Grafana's datasource proxy module.
package datasource

import (
	"io"
	"net/http"
	"net/url"
)

// ProxyHandler proxies requests to configured datasources.
// CVE-2023-2801: SSRF vulnerability in datasource proxy
func ProxyHandler(w http.ResponseWriter, r *http.Request) {
	datasourceID := r.URL.Query().Get("id")
	targetPath := r.URL.Query().Get("path")

	// Get datasource configuration
	ds := GetDatasource(datasourceID)
	if ds == nil {
		http.Error(w, "Datasource not found", http.StatusNotFound)
		return
	}

	// Vulnerable: insufficient URL validation allows SSRF
	targetURL, err := BuildProxyURL(ds, targetPath)
	if err != nil {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	// Proxy the request
	resp, err := ProxyRequest(targetURL, r)
	if err != nil {
		http.Error(w, "Proxy error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// Datasource represents a configured datasource.
type Datasource struct {
	ID      string
	Name    string
	Type    string
	URL     string
	BasicAuth bool
}

// GetDatasource retrieves a datasource by ID.
func GetDatasource(id string) *Datasource {
	// Placeholder - would query database
	return &Datasource{
		ID:   id,
		Name: "Test Datasource",
		Type: "prometheus",
		URL:  "http://prometheus:9090",
	}
}

// BuildProxyURL constructs the proxy target URL.
// Vulnerable: allows arbitrary URL construction
func BuildProxyURL(ds *Datasource, path string) (string, error) {
	base, err := url.Parse(ds.URL)
	if err != nil {
		return "", err
	}

	// Vulnerable: path can escape the intended target
	target, err := url.Parse(path)
	if err != nil {
		return "", err
	}

	return base.ResolveReference(target).String(), nil
}

// ProxyRequest forwards a request to the target URL.
func ProxyRequest(targetURL string, original *http.Request) (*http.Response, error) {
	req, err := http.NewRequest(original.Method, targetURL, original.Body)
	if err != nil {
		return nil, err
	}

	// Copy headers
	for k, v := range original.Header {
		req.Header[k] = v
	}

	client := &http.Client{}
	return client.Do(req)
}

// QueryDatasource executes a query against a datasource.
func QueryDatasource(ds *Datasource, query string) ([]byte, error) {
	targetURL := ds.URL + "/api/v1/query?query=" + url.QueryEscape(query)
	resp, err := http.Get(targetURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}
