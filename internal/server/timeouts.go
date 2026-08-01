package server

import (
	"context"
	"time"
)

func timeoutContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

func (a *App) requestContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return timeoutContext(ctx, a.config.Spec.Limits.RequestTimeout.Duration)
}
