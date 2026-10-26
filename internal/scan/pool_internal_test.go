package scan

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/kartverket/emudhra-checker/internal/inventory"
)

// maxConcurrent returns a scan func that records how many scans run at once.
func maxConcurrent(maximum *atomic.Int32) func(inventory.ImageTarget) ImageResult {
	var active atomic.Int32
	return func(target inventory.ImageTarget) ImageResult {
		current := active.Add(1)
		for {
			observed := maximum.Load()
			if current <= observed || maximum.CompareAndSwap(observed, current) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		active.Add(-1)
		return ImageResult{Image: target.Image, Status: StatusPatched}
	}
}

func TestTargetsLimitsConcurrencyAndPreservesOrder(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		targets := make([]inventory.ImageTarget, 12)
		for index := range targets {
			targets[index].Image = fmt.Sprintf("image-%d", index)
		}

		var maximum atomic.Int32
		results := Targets(t.Context(), targets, 3, maxConcurrent(&maximum))

		if got := maximum.Load(); got != 3 {
			t.Fatalf("observed %d concurrent scans; want exactly the limit of 3", got)
		}
		for index, result := range results {
			if result.Image != targets[index].Image {
				t.Errorf("result %d is for %q, want %q", index, result.Image, targets[index].Image)
			}
		}
	})
}

// TestTargetsKeepsWorkersBusyWithDuplicates covers many rows naming one image
// ahead of other images: the other images must not wait for it.
func TestTargetsKeepsWorkersBusyWithDuplicates(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var targets []inventory.ImageTarget
		for range 10 {
			targets = append(targets, inventory.ImageTarget{Image: "registry.example/big:v1"})
		}
		targets = append(targets,
			inventory.ImageTarget{Image: "registry.example/b:v1"},
			inventory.ImageTarget{Image: "registry.example/c:v1"},
		)

		var maximum atomic.Int32
		Targets(t.Context(), targets, 3, maxConcurrent(&maximum))

		if got := maximum.Load(); got != 3 {
			t.Fatalf("observed %d concurrent scans; want 3 distinct images at once", got)
		}
	})
}

func sameTarget(result ImageResult, target inventory.ImageTarget) bool {
	return result.Cluster == target.Cluster && result.Namespace == target.Namespace &&
		result.Kind == target.Kind && result.Application == target.Application && result.Image == target.Image
}

func TestTargetsScansEachImageOnce(t *testing.T) {
	t.Parallel()
	for _, status := range []string{StatusVulnerable, StatusUnknown, StatusPullError} {
		t.Run(status, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				targets := []inventory.ImageTarget{
					{Cluster: "c1", Namespace: "ns-a", Application: "app-a", Image: "nginx"},
					{
						Cluster:     "c2",
						Namespace:   "ns-b",
						Kind:        "CronJob",
						Application: "b",
						Image:       "docker.io/library/nginx:latest",
					},
					{Cluster: "c2", Namespace: "ns-c", Application: "app-c", Image: "index.docker.io/library/nginx"},
				}
				var scans atomic.Int32
				results := Targets(t.Context(), targets, 3, func(target inventory.ImageTarget) ImageResult {
					scans.Add(1)
					time.Sleep(10 * time.Millisecond)
					return ImageResult{Image: target.Image, Status: status}
				})

				if got := scans.Load(); got != 1 {
					t.Fatalf("performed %d scans for one image; want 1", got)
				}
				for index, result := range results {
					if !sameTarget(result, targets[index]) || result.Status != status {
						t.Errorf("result %d does not match its input target: %#v", index, result)
					}
				}
			})
		})
	}
}

func TestTargetsStopsWhenCanceled(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		targets := []inventory.ImageTarget{{Image: "a"}, {Image: "b"}, {Image: "c"}}
		var scans atomic.Int32
		results := Targets(ctx, targets, 1, func(target inventory.ImageTarget) ImageResult {
			scans.Add(1)
			cancel()
			time.Sleep(time.Millisecond)
			return ImageResult{Image: target.Image, Status: StatusPatched}
		})

		if got := scans.Load(); got != 1 {
			t.Fatalf("performed %d scans; want none after cancel", got)
		}
		if results[0].Status != StatusPatched {
			t.Errorf("first result = %s, want the finished scan", results[0].Status)
		}
		for _, result := range results[1:] {
			if result.Status != StatusUnknown || !strings.Contains(result.Error, "interrupted") || !sameTarget(
				result,
				inventory.ImageTarget{Image: result.Image},
			) {
				t.Errorf("unscanned result = %#v, want UNKNOWN not scanned: interrupted", result)
			}
		}
	})
}
