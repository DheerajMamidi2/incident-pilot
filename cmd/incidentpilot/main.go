package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/dheerajmamidi/incidentpilot/internal/app"
)

func main() {
	config, err := app.LoadConfig(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("incidentpilot listening on http://%s", config.Address)
	if err := app.Run(ctx, config); err != nil {
		log.Fatal(err)
	}
}
