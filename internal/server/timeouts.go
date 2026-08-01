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

func (a *App) serverWriteTimeout() time.Duration {
	operationTimeout := max(
		a.config.Spec.Limits.RequestTimeout.Duration,
		a.config.Spec.Limits.StreamTimeout.Duration,
		a.config.Spec.Limits.ExecTimeout.Duration,
	)
	return saturatingDurationSum(
		a.config.Spec.Limits.RequestTimeout.Duration,
		a.config.Spec.Limits.RequestTimeout.Duration,
		operationTimeout,
		10*time.Second,
	)
}

func saturatingDurationSum(values ...time.Duration) time.Duration {
	const maximum = time.Duration(1<<63 - 1)
	var total time.Duration
	for _, value := range values {
		if value > maximum-total {
			return maximum
		}
		total += value
	}
	return total
}
