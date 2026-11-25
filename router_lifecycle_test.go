// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

package route

import (
	"context"
	"testing"
	"time"
)

func startRouter(r *routerImpl) <-chan error {
	done := make(chan error, 1)
	go func() { done <- r.Start(context.Background()) }()
	return done
}

func waitStart(t *testing.T, done <-chan error, what string) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned %v after %s, want nil", err, what)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Start still running 2s after %s", what)
	}
}

// A Stop that runs before Start stops the router: Start returns at once.
func TestRouter_StopBeforeStartStopsIt(t *testing.T) {
	r := newTestRouter(t)
	if err := r.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	waitStart(t, startRouter(r), "an earlier Stop")
}

// A Stop that runs while Start runs ends it.
func TestRouter_StopEndsARunningStart(t *testing.T) {
	r := newTestRouter(t)
	done := startRouter(r)
	time.Sleep(20 * time.Millisecond)
	if err := r.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	waitStart(t, done, "Stop")
}

// Start and Stop racing from two goroutines always end with Start returned,
// whichever runs first; under -race the pair reports no data race.
func TestRouter_StartAndStopRacing(t *testing.T) {
	for i := 0; i < 50; i++ {
		r := newTestRouter(t)
		done := startRouter(r)
		if err := r.Stop(); err != nil {
			t.Fatalf("stop: %v", err)
		}
		waitStart(t, done, "a racing Stop")
	}
}
