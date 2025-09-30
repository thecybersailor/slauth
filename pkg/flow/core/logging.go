package core

import (
	"log/slog"
	"time"
)

func LoggingFlow[T any]() Flow[T] {
	return func(ctx *Context[T], next func() error) error {
		start := time.Now()
		slog.Info("Flow: Logging - Before", "context", ctx.Data)

		err := next()

		duration := time.Since(start)
		if err != nil {
			slog.Error("Flow: Logging - After (Error)", "error", err, "duration", duration, "context", ctx.Data)
		} else {
			slog.Info("Flow: Logging - After (Success)", "duration", duration, "context", ctx.Data)
		}
		return err
	}
}
