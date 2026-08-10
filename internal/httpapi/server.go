package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dheerajmamidi/incidentpilot/internal/core"
	"github.com/dheerajmamidi/incidentpilot/internal/webui"
)

const defaultMaxBodyBytes int64 = 4096

var (
	resourceIDPattern = regexp.MustCompile(`^inc-[a-zA-Z0-9-]{3,80}$`)
	proposalIDPattern = regexp.MustCompile(`^prop-[a-zA-Z0-9-]{3,80}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	scenarioIDPattern = regexp.MustCompile(`^[a-z0-9-]{3,64}$`)
)

type Options struct {
	RateLimit    int
	RateWindow   time.Duration
	MaxBodyBytes int64
	Clock        func() time.Time
}

type server struct {
	service      *core.Service
	ui           http.Handler
	limiter      *fixedWindowLimiter
	maxBodyBytes int64
}

type contextKey string

const requestIDKey contextKey = "request-id"

type successEnvelope[T any] struct {
	Success bool `json:"success"`
	Data    T    `json:"data"`
}

type errorEnvelope struct {
	Success bool        `json:"success"`
	Error   errorDetail `json:"error"`
}

type errorDetail struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

type healthResponse struct {
	Status  string  `json:"status"`
	Service string  `json:"service"`
	Mode    string  `json:"mode"`
	CostUSD float64 `json:"cost_usd"`
}

type createIncidentRequest struct {
	ScenarioID string `json:"scenario_id"`
}

type approvalRequest struct {
	ProposalID     string `json:"proposal_id"`
	ProposalDigest string `json:"proposal_digest"`
	Actor          string `json:"actor"`
}

type rejectionRequest struct {
	ProposalID     string `json:"proposal_id"`
	ProposalDigest string `json:"proposal_digest"`
	Actor          string `json:"actor"`
	Reason         string `json:"reason"`
}

func NewHandler(service *core.Service, options Options) http.Handler {
	if service == nil {
		service = core.NewService(core.NewMemoryRepository(), core.Dependencies{})
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	rateLimit := options.RateLimit
	if rateLimit <= 0 {
		rateLimit = 30
	}
	rateWindow := options.RateWindow
	if rateWindow <= 0 {
		rateWindow = time.Minute
	}
	maxBodyBytes := options.MaxBodyBytes
	if maxBodyBytes <= 0 {
		maxBodyBytes = defaultMaxBodyBytes
	}
	apiServer := &server{
		service:      service,
		ui:           webui.NewHandler(),
		limiter:      newFixedWindowLimiter(rateLimit, rateWindow, clock),
		maxBodyBytes: maxBodyBytes,
	}
	return http.HandlerFunc(apiServer.serveHTTP)
}

func (server *server) serveHTTP(response http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(response, request)
	requestID := newRequestID()
	response.Header().Set("X-Request-ID", requestID)
	request = request.WithContext(context.WithValue(request.Context(), requestIDKey, requestID))
	defer func() {
		if recover() != nil {
			log.Printf("incidentpilot: recovered request panic request_id=%s", requestID)
			writeError(response, request, http.StatusInternalServerError, "internal_error", "The request could not be completed.")
		}
	}()
	if strings.HasPrefix(request.URL.Path, "/api/") || request.URL.Path == "/api" {
		response.Header().Set("Cache-Control", "no-store")
		server.routeAPI(response, request)
		return
	}
	server.ui.ServeHTTP(response, request)
}

func (server *server) routeAPI(response http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/api/health":
		if !requireMethod(response, request, http.MethodGet) {
			return
		}
		writeJSON(response, http.StatusOK, successEnvelope[healthResponse]{
			Success: true,
			Data:    healthResponse{Status: "ok", Service: "incidentpilot", Mode: "deterministic-local", CostUSD: 0},
		})
		return
	case "/api/scenarios":
		if !requireMethod(response, request, http.MethodGet) {
			return
		}
		writeJSON(response, http.StatusOK, successEnvelope[[]core.Scenario]{Success: true, Data: server.service.ListScenarios()})
		return
	case "/api/incidents":
		if !requireMethod(response, request, http.MethodPost) {
			return
		}
		if !server.authorizeMutation(response, request) {
			return
		}
		server.createIncident(response, request)
		return
	}

	if !strings.HasPrefix(request.URL.Path, "/api/incidents/") {
		writeError(response, request, http.StatusNotFound, "not_found", "Resource not found.")
		return
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/api/incidents/"), "/")
	if len(segments) == 1 {
		if !requireMethod(response, request, http.MethodGet) {
			return
		}
		if !resourceIDPattern.MatchString(segments[0]) {
			writeError(response, request, http.StatusBadRequest, "invalid_request", "The request could not be processed.")
			return
		}
		server.getIncident(response, request, segments[0])
		return
	}
	if len(segments) != 2 || (segments[1] != "approve" && segments[1] != "reject") {
		writeError(response, request, http.StatusNotFound, "not_found", "Resource not found.")
		return
	}
	if !requireMethod(response, request, http.MethodPost) {
		return
	}
	if !resourceIDPattern.MatchString(segments[0]) {
		writeError(response, request, http.StatusBadRequest, "invalid_request", "The request could not be processed.")
		return
	}
	if !server.authorizeMutation(response, request) {
		return
	}
	if segments[1] == "approve" {
		server.approveIncident(response, request, segments[0])
		return
	}
	server.rejectIncident(response, request, segments[0])
}

func (server *server) createIncident(response http.ResponseWriter, request *http.Request) {
	var input createIncidentRequest
	if !decodeStrictJSON(response, request, server.maxBodyBytes, &input) {
		return
	}
	input.ScenarioID = strings.TrimSpace(input.ScenarioID)
	if !scenarioIDPattern.MatchString(input.ScenarioID) {
		writeError(response, request, http.StatusBadRequest, "invalid_request", "The request could not be processed.")
		return
	}
	incident, err := server.service.CreateIncident(request.Context(), input.ScenarioID)
	if err != nil {
		writeServiceError(response, request, err)
		return
	}
	response.Header().Set("Location", "/api/incidents/"+incident.ID)
	writeJSON(response, http.StatusCreated, successEnvelope[core.Incident]{Success: true, Data: incident})
}

func (server *server) getIncident(response http.ResponseWriter, request *http.Request, id string) {
	incident, err := server.service.GetIncident(request.Context(), id)
	if err != nil {
		writeServiceError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, successEnvelope[core.Incident]{Success: true, Data: incident})
}

func (server *server) approveIncident(response http.ResponseWriter, request *http.Request, id string) {
	var input approvalRequest
	if !decodeStrictJSON(response, request, server.maxBodyBytes, &input) {
		return
	}
	if !validDecisionFields(input.ProposalID, input.ProposalDigest, input.Actor) {
		writeError(response, request, http.StatusBadRequest, "invalid_request", "The request could not be processed.")
		return
	}
	incident, err := server.service.Approve(request.Context(), id, core.ApprovalInput{
		ProposalID:     input.ProposalID,
		ProposalDigest: input.ProposalDigest,
		Actor:          input.Actor,
	})
	if err != nil {
		writeServiceError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, successEnvelope[core.Incident]{Success: true, Data: incident})
}

func (server *server) rejectIncident(response http.ResponseWriter, request *http.Request, id string) {
	var input rejectionRequest
	if !decodeStrictJSON(response, request, server.maxBodyBytes, &input) {
		return
	}
	if !validDecisionFields(input.ProposalID, input.ProposalDigest, input.Actor) || !validText(input.Reason, 300) {
		writeError(response, request, http.StatusBadRequest, "invalid_request", "The request could not be processed.")
		return
	}
	incident, err := server.service.Reject(request.Context(), id, core.RejectionInput{
		ProposalID:     input.ProposalID,
		ProposalDigest: input.ProposalDigest,
		Actor:          input.Actor,
		Reason:         input.Reason,
	})
	if err != nil {
		writeServiceError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, successEnvelope[core.Incident]{Success: true, Data: incident})
}

func (server *server) authorizeMutation(response http.ResponseWriter, request *http.Request) bool {
	if !sameOrigin(request) {
		writeError(response, request, http.StatusForbidden, "forbidden", "The request is not allowed.")
		return false
	}
	allowed, retryAfter := server.limiter.Allow(clientAddress(request))
	if !allowed {
		response.Header().Set("Retry-After", strconv.Itoa(max(1, int(retryAfter.Round(time.Second).Seconds()))))
		writeError(response, request, http.StatusTooManyRequests, "rate_limited", "Too many state-changing requests. Try again later.")
		return false
	}
	return true
}

func sameOrigin(request *http.Request) bool {
	fetchSite := strings.ToLower(strings.TrimSpace(request.Header.Get("Sec-Fetch-Site")))
	if fetchSite != "" && fetchSite != "same-origin" && fetchSite != "none" {
		return false
	}
	originValue := strings.TrimSpace(request.Header.Get("Origin"))
	if originValue == "" {
		return true
	}
	origin, err := url.Parse(originValue)
	if err != nil || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || origin.Path != "" {
		return false
	}
	expectedScheme := "http"
	if request.TLS != nil {
		expectedScheme = "https"
	}
	return strings.EqualFold(origin.Scheme, expectedScheme) && strings.EqualFold(origin.Host, request.Host)
}

func decodeStrictJSON(response http.ResponseWriter, request *http.Request, maxBytes int64, target any) bool {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(response, request, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json.")
		return false
	}
	request.Body = http.MaxBytesReader(response, request.Body, maxBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeError(response, request, http.StatusRequestEntityTooLarge, "payload_too_large", "The request body is too large.")
			return false
		}
		writeError(response, request, http.StatusBadRequest, "invalid_json", "The JSON request could not be processed.")
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeError(response, request, http.StatusRequestEntityTooLarge, "payload_too_large", "The request body is too large.")
			return false
		}
		writeError(response, request, http.StatusBadRequest, "invalid_json", "The JSON request could not be processed.")
		return false
	}
	return true
}

func requireMethod(response http.ResponseWriter, request *http.Request, method string) bool {
	if request.Method == method {
		return true
	}
	response.Header().Set("Allow", method)
	writeError(response, request, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed for this resource.")
	return false
}

func writeServiceError(response http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, core.ErrScenarioNotFound):
		writeError(response, request, http.StatusNotFound, "not_found", "Resource not found.")
	case errors.Is(err, core.ErrIncidentNotFound):
		writeError(response, request, http.StatusNotFound, "not_found", "Resource not found.")
	case errors.Is(err, core.ErrInvalidInput):
		writeError(response, request, http.StatusBadRequest, "invalid_request", "The request could not be processed.")
	case errors.Is(err, core.ErrInvalidTransition), errors.Is(err, core.ErrProposalMismatch):
		writeError(response, request, http.StatusConflict, "conflict", "The request conflicts with the current incident state.")
	case errors.Is(err, core.ErrConcurrentUpdate):
		writeError(response, request, http.StatusConflict, "conflict", "The request conflicts with the current incident state.")
	default:
		log.Printf("incidentpilot: service request failed request_id=%s", requestID(request))
		writeError(response, request, http.StatusInternalServerError, "internal_error", "The request could not be completed.")
	}
}

func writeError(response http.ResponseWriter, request *http.Request, status int, code, message string) {
	writeJSON(response, status, errorEnvelope{
		Success: false,
		Error:   errorDetail{Code: code, Message: message, RequestID: requestID(request)},
	})
}

func writeJSON(response http.ResponseWriter, status int, payload any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	if err := json.NewEncoder(response).Encode(payload); err != nil {
		log.Printf("incidentpilot: response encoding failed")
	}
}

func setSecurityHeaders(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'")
	response.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	response.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	response.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("X-Frame-Options", "DENY")
	if request.TLS != nil {
		response.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
}

func validDecisionFields(proposalID, digest, actor string) bool {
	return proposalIDPattern.MatchString(strings.TrimSpace(proposalID)) &&
		digestPattern.MatchString(strings.TrimSpace(digest)) &&
		validText(actor, 100)
}

func validText(value string, limit int) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || len(trimmed) > limit {
		return false
	}
	for _, character := range trimmed {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func requestID(request *http.Request) string {
	if id, ok := request.Context().Value(requestIDKey).(string); ok && id != "" {
		return id
	}
	return "req-unavailable"
}

func newRequestID() string {
	buffer := make([]byte, 8)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("req-%d", time.Now().UTC().UnixNano())
	}
	return "req-" + hex.EncodeToString(buffer)
}

func clientAddress(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	if request.RemoteAddr == "" {
		return "unknown"
	}
	return request.RemoteAddr
}

type rateWindowEntry struct {
	count     int
	resetTime time.Time
}

type fixedWindowLimiter struct {
	mu         sync.Mutex
	entries    map[string]rateWindowEntry
	limit      int
	window     time.Duration
	clock      func() time.Time
	maxEntries int
}

func newFixedWindowLimiter(limit int, window time.Duration, clock func() time.Time) *fixedWindowLimiter {
	return &fixedWindowLimiter{
		entries:    make(map[string]rateWindowEntry),
		limit:      limit,
		window:     window,
		clock:      clock,
		maxEntries: 4096,
	}
}

func (limiter *fixedWindowLimiter) Allow(key string) (bool, time.Duration) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	now := limiter.clock().UTC()
	entry, exists := limiter.entries[key]
	if !exists || !now.Before(entry.resetTime) {
		if !exists && len(limiter.entries) >= limiter.maxEntries {
			limiter.removeExpired(now)
			if len(limiter.entries) >= limiter.maxEntries {
				return false, limiter.window
			}
		}
		limiter.entries[key] = rateWindowEntry{count: 1, resetTime: now.Add(limiter.window)}
		return true, 0
	}
	if entry.count >= limiter.limit {
		return false, entry.resetTime.Sub(now)
	}
	entry.count++
	limiter.entries[key] = entry
	return true, 0
}

func (limiter *fixedWindowLimiter) removeExpired(now time.Time) {
	for key, entry := range limiter.entries {
		if !now.Before(entry.resetTime) {
			delete(limiter.entries, key)
		}
	}
}
