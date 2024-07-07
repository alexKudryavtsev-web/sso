package app

import (
	"log/slog"
	grpcapp "sso/internal/app/grpc"
	"time"
)

type App struct {
	GRPCServer *grpcapp.App
}

func New(log *slog.Logger, gprcPort int, storagePath string, tokenTTL time.Duration) *App {

	grpcApp := grpcapp.New(log, gprcPort)

	return &App{
		GRPCServer: grpcApp,
	}
}
