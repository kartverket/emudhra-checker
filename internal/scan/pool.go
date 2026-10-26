package scan

import (
	"context"
	"sync"

	"github.com/kartverket/emudhra-checker/internal/inventory"
	"github.com/kartverket/emudhra-checker/internal/registry"
)

// Targets scans every distinct image once, at most parallelism at a time,
// and returns one result per target in input order. Targets that name the same
// image (see registry.CanonicalName) share its result, whatever the status, so
// no image is pulled twice in a run. Once ctx is canceled no new scans start,
// and images that were not started are reported as UNKNOWN.
func Targets(
	ctx context.Context,
	targets []inventory.ImageTarget,
	parallelism int,
	scan func(inventory.ImageTarget) ImageResult,
) []ImageResult {
	rows := make(map[string][]int) // image -> indexes of the targets naming it
	var images []string
	for index, target := range targets {
		image := registry.CanonicalName(target.Image)
		if _, seen := rows[image]; !seen {
			images = append(images, image)
		}
		rows[image] = append(rows[image], index)
	}

	scanned := make([]ImageResult, len(images))
	for i, image := range images {
		scanned[i] = newResult(targets[rows[image][0]])
		scanned[i].Error = "not scanned: interrupted"
	}

	// Workers only ever get distinct images, so duplicates never hold a slot.
	jobs := make(chan int)
	var workers sync.WaitGroup
	for range min(parallelism, len(images)) {
		workers.Go(func() {
			for i := range jobs {
				scanned[i] = scan(targets[rows[images[i]][0]])
			}
		})
	}
dispatch:
	for i := range images {
		if ctx.Err() != nil {
			break
		}
		select {
		case jobs <- i:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(jobs)
	workers.Wait()

	results := make([]ImageResult, len(targets))
	for i, image := range images {
		for _, row := range rows[image] {
			results[row] = resultForTarget(scanned[i], targets[row])
		}
	}
	return results
}
