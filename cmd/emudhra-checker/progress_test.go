package main

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestProgress(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var logs bytes.Buffer
		tracker := newProgress(slog.New(slog.NewTextHandler(&logs, nil)))
		stop := make(chan struct{})
		var done sync.WaitGroup
		done.Go(func() { tracker.run(t.Context(), progressInterval, stop) })

		tracker.start("big")
		time.Sleep(10 * time.Second)
		tracker.start("small")
		tracker.start("quick")
		tracker.finish("quick")
		time.Sleep(21 * time.Second)
		synctest.Wait()

		want := `msg="still scanning" finished=1 in_progress=2 images="big (30s), small (20s)"`
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log = %q, want it to contain %q", logs.String(), want)
		}

		tracker.finish("big")
		tracker.finish("small")
		logs.Reset()
		time.Sleep(progressInterval)
		synctest.Wait()
		if logs.Len() != 0 {
			t.Errorf("log = %q, want nothing while no image is scanned", logs.String())
		}

		close(stop)
		done.Wait()
	})
}
