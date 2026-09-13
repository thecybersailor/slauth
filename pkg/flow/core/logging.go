package core

import (
	"log/slog"
	"time"
)

func LoggingFlow[T any]() Flow[T] {
	return func(ctx *Context[T], next func() error) error {
		start := time.Now()
		slog.Info("auth flow started")

		err := next()

		duration := time.Since(start)
		if err != nil {
			slog.Error("auth flow completed", "success", false, "error", err, "duration", duration)
		} else {
			slog.Info("auth flow completed", "success", true, "duration", duration)
		}
		return err
	}
}
