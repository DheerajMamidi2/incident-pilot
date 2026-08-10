package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dheerajmamidi/incidentpilot/internal/core"
)

func TestIncidentAPIHappyPathRequiresExplicitDigestBoundApproval(t *testing.T) {
	handler := newTestHandler()

	health := performRequest(t, handler, http.MethodGet, "/api/health", nil, nil)
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d, want %d", health.Code, http.StatusOK)
	}
	var healthBody successEnvelope[healthResponse]
	decodeResponse(t, health, &healthBody)
	if !healthBody.Success || healthBody.Data.Status != "ok" {
		t.Fatalf("health response = %#v", healthBody)
	}

	scenarios := performRequest(t, handler, http.MethodGet, "/api/scenarios", nil, nil)
	if scenarios.Code != http.StatusOK {
		t.Fatalf("scenario status = %d", scenarios.Code)
	}
	var scenariosBody successEnvelope[[]core.Scenario]
	decodeResponse(t, scenarios, &scenariosBody)
	if len(scenariosBody.Data) < 3 {
		t.Fatalf("scenario count = %d, want at least 3", len(scenariosBody.Data))
	}

	createdResponse := performJSON(t, handler, http.MethodPost, "/api/incidents", `{"scenario_id":"checkout-latency"}`, "http://example.test")
	if createdResponse.Code != http.StatusCreated {
		t.Fatalf("create status = %d body = %s", createdResponse.Code, createdResponse.Body.String())
	}
	var createdBody successEnvelope[core.Incident]
	decodeResponse(t, createdResponse, &createdBody)
	created := createdBody.Data
	if created.State != core.StateAwaitingApproval || created.Proposal == nil {
		t.Fatalf("created incident = %#v", created)
	}
	if location := createdResponse.Header().Get("Location"); location != "/api/incidents/"+created.ID {
		t.Fatalf("Location = %q", location)
	}

	getResponse := performRequest(t, handler, http.MethodGet, "/api/incidents/"+created.ID, nil, nil)
	if getResponse.Code != http.StatusOK {
		t.Fatalf("get status = %d", getResponse.Code)
	}

	approvalBody := `{"proposal_id":"` + created.Proposal.ID + `","proposal_digest":"` + created.Proposal.Digest + `","actor":"demo.operator"}`
	approvedResponse := performJSON(t, handler, http.MethodPost, "/api/incidents/"+created.ID+"/approve", approvalBody, "http://example.test")
	if approvedResponse.Code != http.StatusOK {
		t.Fatalf("approve status = %d body = %s", approvedResponse.Code, approvedResponse.Body.String())
	}
	var approvedBody successEnvelope[core.Incident]
	decodeResponse(t, approvedResponse, &approvedBody)
	if approvedBody.Data.State != core.StateResolved || approvedBody.Data.Verification == nil || !approvedBody.Data.Verification.FreshTelemetry {
		t.Fatalf("approved incident = %#v", approvedBody.Data)
	}
}

func TestRejectEndpointEscalatesAndNeverExecutes(t *testing.T) {
	handler := newTestHandler()
	created := createIncident(t, handler, "dependency-saturation")
	body := `{"proposal_id":"` + created.Proposal.ID + `","proposal_digest":"` + created.Proposal.Digest + `","actor":"incident.commander","reason":"Coordinate with the owning team."}`

	response := performJSON(t, handler, http.MethodPost, "/api/incidents/"+created.ID+"/reject", body, "http://example.test")
	if response.Code != http.StatusOK {
		t.Fatalf("reject status = %d body = %s", response.Code, response.Body.String())
	}
	var envelope successEnvelope[core.Incident]
	decodeResponse(t, response, &envelope)
	if envelope.Data.State != core.StateEscalated || envelope.Data.Execution != nil {
		t.Fatalf("rejected incident = %#v", envelope.Data)
	}
}

func TestJSONBoundaryRejectsUnknownTrailingOversizedAndWrongMediaBodies(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		wantStatus  int
	}{
		{name: "unknown field", contentType: "application/json", body: `{"scenario_id":"checkout-latency","command":"rm -rf /"}`, wantStatus: http.StatusBadRequest},
		{name: "trailing object", contentType: "application/json", body: `{"scenario_id":"checkout-latency"}{}`, wantStatus: http.StatusBadRequest},
		{name: "malformed", contentType: "application/json", body: `{"scenario_id":`, wantStatus: http.StatusBadRequest},
		{name: "empty", contentType: "application/json", body: ``, wantStatus: http.StatusBadRequest},
		{name: "wrong media type", contentType: "text/plain", body: `{"scenario_id":"checkout-latency"}`, wantStatus: http.StatusUnsupportedMediaType},
		{name: "oversized", contentType: "application/json", body: `{"scenario_id":"` + strings.Repeat("a", 5000) + `"}`, wantStatus: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			headers := map[string]string{"Content-Type": test.contentType, "Origin": "http://example.test"}
			response := performRequest(t, newTestHandler(), http.MethodPost, "/api/incidents", strings.NewReader(test.body), headers)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, test.wantStatus, response.Body.String())
			}
			assertGenericError(t, response)
		})
	}
}

func TestMutationEndpointsEnforceSameOrigin(t *testing.T) {
	handler := newTestHandler()
	crossOrigin := performJSON(t, handler, http.MethodPost, "/api/incidents", `{"scenario_id":"checkout-latency"}`, "https://evil.example")
	if crossOrigin.Code != http.StatusForbidden {
		t.Fatalf("cross-origin status = %d, want %d", crossOrigin.Code, http.StatusForbidden)
	}
	assertGenericError(t, crossOrigin)

	crossSite := performRequest(t, handler, http.MethodPost, "/api/incidents", strings.NewReader(`{"scenario_id":"checkout-latency"}`), map[string]string{
		"Content-Type":   "application/json",
		"Sec-Fetch-Site": "cross-site",
	})
	if crossSite.Code != http.StatusForbidden {
		t.Fatalf("cross-site status = %d, want %d", crossSite.Code, http.StatusForbidden)
	}

	cliRequest := performRequest(t, handler, http.MethodPost, "/api/incidents", strings.NewReader(`{"scenario_id":"checkout-latency"}`), map[string]string{"Content-Type": "application/json"})
	if cliRequest.Code != http.StatusCreated {
		t.Fatalf("non-browser client status = %d, want %d", cliRequest.Code, http.StatusCreated)
	}
}

func TestStateChangingEndpointsAreRateLimitedByRemoteAddress(t *testing.T) {
	service := core.NewService(core.NewMemoryRepository(), core.Dependencies{})
	handler := NewHandler(service, Options{RateLimit: 2, RateWindow: time.Minute, MaxBodyBytes: 4096})

	for attempt := 1; attempt <= 3; attempt++ {
		response := performJSON(t, handler, http.MethodPost, "/api/incidents", `{"scenario_id":"checkout-latency"}`, "http://example.test")
		if attempt < 3 && response.Code != http.StatusCreated {
			t.Fatalf("attempt %d status = %d, want %d", attempt, response.Code, http.StatusCreated)
		}
		if attempt == 3 {
			if response.Code != http.StatusTooManyRequests {
				t.Fatalf("rate-limited status = %d, want %d", response.Code, http.StatusTooManyRequests)
			}
			if response.Header().Get("Retry-After") == "" {
				t.Fatal("missing Retry-After header")
			}
			assertGenericError(t, response)
		}
	}
}

func TestSecurityHeadersAndStaticDashboard(t *testing.T) {
	handler := newTestHandler()
	response := performRequest(t, handler, http.MethodGet, "/", nil, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d", response.Code)
	}
	if !strings.Contains(response.Body.String(), "IncidentPilot") {
		t.Fatal("dashboard does not contain product name")
	}
	csp := response.Header().Get("Content-Security-Policy")
	if csp == "" || strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "default-src 'self'") {
		t.Fatalf("CSP = %q", csp)
	}
	for header, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := response.Header().Get(header); got != want {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}

	asset := performRequest(t, handler, http.MethodGet, "/assets/app.js", nil, nil)
	if asset.Code != http.StatusOK || !strings.Contains(asset.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("asset status/content-type = %d/%q", asset.Code, asset.Header().Get("Content-Type"))
	}
}

func TestAPIErrorsAreGenericAndMethodsAreBounded(t *testing.T) {
	handler := newTestHandler()
	tests := []struct {
		method string
		path   string
		body   io.Reader
		want   int
	}{
		{method: http.MethodGet, path: "/api/incidents/inc-does-not-exist", want: http.StatusNotFound},
		{method: http.MethodDelete, path: "/api/incidents/inc-does-not-exist", want: http.StatusMethodNotAllowed},
		{method: http.MethodGet, path: "/api/not-a-route", want: http.StatusNotFound},
		{method: http.MethodPost, path: "/api/incidents/not_valid/approve", body: strings.NewReader(`{}`), want: http.StatusBadRequest},
	}
	for _, test := range tests {
		response := performRequest(t, handler, test.method, test.path, test.body, map[string]string{"Content-Type": "application/json"})
		if response.Code != test.want {
			t.Fatalf("%s %s status = %d, want %d; body=%s", test.method, test.path, response.Code, test.want, response.Body.String())
		}
		assertGenericError(t, response)
		if strings.Contains(strings.ToLower(response.Body.String()), "stack") || strings.Contains(response.Body.String(), "incident not found") {
			t.Fatalf("response leaked internal detail: %s", response.Body.String())
		}
	}
}

func newTestHandler() http.Handler {
	return NewHandler(core.NewService(core.NewMemoryRepository(), core.Dependencies{}), Options{})
}

func createIncident(t *testing.T, handler http.Handler, scenarioID string) core.Incident {
	t.Helper()
	response := performJSON(t, handler, http.MethodPost, "/api/incidents", `{"scenario_id":"`+scenarioID+`"}`, "http://example.test")
	if response.Code != http.StatusCreated {
		t.Fatalf("create status = %d body = %s", response.Code, response.Body.String())
	}
	var envelope successEnvelope[core.Incident]
	decodeResponse(t, response, &envelope)
	return envelope.Data
}

func performJSON(t *testing.T, handler http.Handler, method, path, body, origin string) *httptest.ResponseRecorder {
	t.Helper()
	headers := map[string]string{"Content-Type": "application/json"}
	if origin != "" {
		headers["Origin"] = origin
	}
	return performRequest(t, handler, method, path, strings.NewReader(body), headers)
}

func performRequest(t *testing.T, handler http.Handler, method, path string, body io.Reader, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, "http://example.test"+path, body)
	request.RemoteAddr = "192.0.2.10:4242"
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func decodeResponse(t *testing.T, response *httptest.ResponseRecorder, target any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(response.Body.Bytes()))
	if err := decoder.Decode(target); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, response.Body.String())
	}
}

func assertGenericError(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	var envelope errorEnvelope
	decodeResponse(t, response, &envelope)
	if envelope.Success || envelope.Error.Code == "" || envelope.Error.Message == "" || envelope.Error.RequestID == "" {
		t.Fatalf("error envelope = %#v", envelope)
	}
}

func TestHandlerDoesNotRequireExternalServices(t *testing.T) {
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.test/api/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	newTestHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
}
