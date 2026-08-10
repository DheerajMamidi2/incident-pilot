package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dheerajmamidi/incidentpilot/internal/core"
	"github.com/dheerajmamidi/incidentpilot/internal/httpapi"
)

const defaultAddress = "127.0.0.1:8080"

type Config struct {
	Address string
}

func LoadConfig(getenv func(string) string) (Config, error) {
	address := defaultAddress
	if configured := getenv("INCIDENTPILOT_ADDR"); configured != "" {
		if strings.TrimSpace(configured) != configured || strings.ContainsAny(configured, "\r\n\x00") {
			return Config{}, errors.New("INCIDENTPILOT_ADDR is invalid")
		}
		address = configured
	}
	if err := validateAddress(address); err != nil {
		return Config{}, err
	}
	return Config{Address: address}, nil
}

func NewHTTPServer(config Config) *http.Server {
	service := core.NewService(core.NewMemoryRepository(), core.Dependencies{})
	return &http.Server{
		Addr:              config.Address,
		Handler:           httpapi.NewHandler(service, httpapi.Options{}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
}

func Run(ctx context.Context, config Config) error {
	server := NewHTTPServer(config)
	result := make(chan error, 1)
	go func() {
		result <- server.ListenAndServe()
	}()

	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("shutdown server: %w", err)
		}
		return nil
	}
}

func validateAddress(address string) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil || host == "" || portText == "" {
		return errors.New("INCIDENTPILOT_ADDR must be a host:port pair")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("INCIDENTPILOT_ADDR contains an invalid port")
	}
	if strings.ContainsAny(host, " \t\r\n\x00") {
		return errors.New("INCIDENTPILOT_ADDR contains an invalid host")
	}
	return nil
}
