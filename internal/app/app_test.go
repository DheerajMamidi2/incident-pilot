package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLoadConfigDefaultsAndValidatesAddress(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "default", want: "127.0.0.1:8080"},
		{name: "explicit", value: "0.0.0.0:9090", want: "0.0.0.0:9090"},
		{name: "missing port", value: "localhost", wantErr: true},
		{name: "bad port", value: "127.0.0.1:99999", wantErr: true},
		{name: "control character", value: "127.0.0.1:8080\n", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, err := LoadConfig(func(key string) string {
				if key == "INCIDENTPILOT_ADDR" {
					return test.value
				}
				return ""
			})
			if (err != nil) != test.wantErr {
				t.Fatalf("LoadConfig() error = %v, wantErr %v", err, test.wantErr)
			}
			if !test.wantErr && config.Address != test.want {
				t.Fatalf("address = %q, want %q", config.Address, test.want)
			}
		})
	}
}

func TestNewHTTPServerUsesDefensiveTimeoutsAndLiveHandler(t *testing.T) {
	server := NewHTTPServer(Config{Address: "127.0.0.1:8080"})
	if server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 || server.WriteTimeout <= 0 || server.IdleTimeout <= 0 || server.MaxHeaderBytes > 32*1024 {
		t.Fatalf("unsafe server limits: %#v", server)
	}
	request := httptest.NewRequest(http.MethodGet, "http://example.test/api/health", nil)
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("health status = %d", response.Code)
	}
	if server.ReadHeaderTimeout > 10*time.Second {
		t.Fatalf("ReadHeaderTimeout = %v", server.ReadHeaderTimeout)
	}
}
