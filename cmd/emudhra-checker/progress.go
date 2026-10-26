package main

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	progressInterval  = 30 * time.Second
	durationPrecision = 100 * time.Millisecond
)

// progress tracks the images being scanned and, while any are running, logs
// them every interval, so a long download does not look like a hang.
type progress struct {
	logger   *slog.Logger
	mu       sync.Mutex
	started  map[string]time.Time
	finished int
}

func newProgress(logger *slog.Logger) *progress {
	return &progress{logger: logger, started: make(map[string]time.Time)}
}

// start records that image is being scanned and returns the start time.
func (p *progress) start(image string) time.Time {
	now := time.Now()
	p.mu.Lock()
	p.started[image] = now
	p.mu.Unlock()
	return now
}

func (p *progress) finish(image string) {
	p.mu.Lock()
	delete(p.started, image)
	p.finished++
	p.mu.Unlock()
}

// run logs the images still being scanned every interval until stop is
// closed or ctx is canceled.
func (p *progress) run(ctx context.Context, interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			p.report(ctx, now)
		}
	}
}

func (p *progress) report(ctx context.Context, now time.Time) {
	type running struct {
		image string
		start time.Time
	}
	p.mu.Lock()
	images := make([]running, 0, len(p.started))
	for image, start := range p.started {
		images = append(images, running{image, start})
	}
	finished := p.finished
	p.mu.Unlock()
	if len(images) == 0 {
		return
	}

	slices.SortFunc(images, func(a, b running) int { return a.start.Compare(b.start) })
	described := make([]string, 0, len(images))
	for _, image := range images {
		described = append(described, fmt.Sprintf("%s (%s)", image.image, now.Sub(image.start).Round(time.Second)))
	}
	p.logger.InfoContext(ctx, "still scanning",
		"finished", finished,
		"in_progress", len(images),
		"images", strings.Join(described, ", "),
	)
}
