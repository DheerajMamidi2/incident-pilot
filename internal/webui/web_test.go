package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEmbeddedDashboardAssets(t *testing.T) {
	tests := []struct {
		path        string
		contentType string
		contains    string
		cache       string
	}{
		{path: "/", contentType: "text/html", contains: "IncidentPilot", cache: "no-store"},
		{path: "/index.html", contentType: "text/html", contains: "Human-gated", cache: "no-store"},
		{path: "/assets/styles.css", contentType: "text/css", contains: ":root", cache: "public"},
		{path: "/assets/app.js", contentType: "text/javascript", contains: "AWAITING_APPROVAL", cache: "public"},
		{path: "/favicon.svg", contentType: "image/svg+xml", contains: "<svg", cache: "public"},
	}
	handler := NewHandler()
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://example.test"+test.path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d", response.Code)
			}
			if !strings.Contains(response.Header().Get("Content-Type"), test.contentType) {
				t.Fatalf("Content-Type = %q", response.Header().Get("Content-Type"))
			}
			if !strings.Contains(response.Header().Get("Cache-Control"), test.cache) {
				t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
			}
			if !strings.Contains(response.Body.String(), test.contains) {
				t.Fatalf("body does not contain %q", test.contains)
			}
		})
	}
}

func TestDashboardSurfacesAuditHashProof(t *testing.T) {
	handler := NewHandler()

	index := httptest.NewRecorder()
	handler.ServeHTTP(index, httptest.NewRequest(http.MethodGet, "http://example.test/", nil))
	if !strings.Contains(index.Body.String(), `id="audit-anchor"`) {
		t.Fatal("dashboard does not expose an audit anchor")
	}

	script := httptest.NewRecorder()
	handler.ServeHTTP(script, httptest.NewRequest(http.MethodGet, "http://example.test/assets/app.js", nil))
	for _, expected := range []string{"renderAuditAnchor", "timeline-meta", "shortHash", "eventTime.dateTime"} {
		if !strings.Contains(script.Body.String(), expected) {
			t.Fatalf("dashboard script does not contain %q", expected)
		}
	}
}

func TestEmbeddedDashboardBoundsMethodsAndPaths(t *testing.T) {
	handler := NewHandler()

	post := httptest.NewRecorder()
	handler.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "http://example.test/", nil))
	if post.Code != http.StatusMethodNotAllowed || post.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST status/Allow = %d/%q", post.Code, post.Header().Get("Allow"))
	}

	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "http://example.test/assets/missing.js", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d", missing.Code)
	}

	head := httptest.NewRecorder()
	handler.ServeHTTP(head, httptest.NewRequest(http.MethodHead, "http://example.test/assets/app.js", nil))
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Fatalf("HEAD status/body = %d/%d", head.Code, head.Body.Len())
	}
}
