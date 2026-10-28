// Command emudhra-checker scans OCI/Docker images for distrusted eMudhra
// certificates, including certificates in Java trust stores.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/pflag"

	"github.com/kartverket/emudhra-checker/internal/certdb"
	"github.com/kartverket/emudhra-checker/internal/inventory"
	"github.com/kartverket/emudhra-checker/internal/report"
	"github.com/kartverket/emudhra-checker/internal/scan"
)

// Exit codes, documented in README.md.
const (
	exitPatched     = 0
	exitVulnerable  = 1
	exitUnknown     = 2
	exitUsage       = 2
	exitConfigError = 3
	exitInterrupted = 130 // 128 + SIGINT
)

const (
	outputTable = "table"
	outputJSON  = "json"
	outputCSV   = "csv"
)

const (
	maxParallelImages = 10
	parallelismEnvVar = "CERTIFICATECHECKER_PARALLELISM"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// After the first signal cancels ctx, a second one ends the process at once.
	context.AfterFunc(ctx, stop)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

type options struct {
	images          []string
	imageFiles      []string
	certificateFile string
	output          string
	parallelism     int
	parallelismSet  bool
	local           bool
}

// parseFlags parses the command line. Help goes to stderr.
func parseFlags(args []string, stderr io.Writer) (options, error) {
	opts := options{output: outputTable}
	flags := pflag.NewFlagSet("emudhra-checker", pflag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.SortFlags = false

	flags.FuncP("image-file", "f",
		"CSV `FILE` with namespace, name, image and an optional Kubernetes kind column; "+
			"repeat for several clusters (the file name is the cluster name); - reads stdin",
		func(value string) error {
			opts.imageFiles = append(opts.imageFiles, value)
			return nil
		})
	flags.FuncP("output", "o", "output `FORMAT`: table (default), csv, or json (one object per image)",
		func(value string) error {
			switch value {
			case outputTable, outputJSON, outputCSV:
				opts.output = value
				return nil
			}
			return errors.New("must be table, json or csv")
		})
	flags.BoolVarP(&opts.local, "local", "l", false,
		"read the images from the local Docker installation (docker image save), not from their registries")
	flags.StringVarP(&opts.certificateFile, "certificates", "c", "",
		"certificate database JSON `FILE` (default: the copy built into the binary)")
	flags.Func("parallel", fmt.Sprintf(
		"`N` images to scan at the same time, 1-%d (default: %s, else %d)",
		maxParallelImages, parallelismEnvVar, maxParallelImages,
	), func(value string) error {
		var err error
		opts.parallelism, err = parseParallelism(value)
		opts.parallelismSet = true
		return err
	})

	err := flags.Parse(args)
	opts.images = flags.Args()
	return opts, err
}

func parseParallelism(value string) (int, error) {
	parallelism, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, errors.New("must be an integer")
	}
	if parallelism < 1 || parallelism > maxParallelImages {
		return 0, fmt.Errorf("must be between 1 and %d", maxParallelImages)
	}
	return parallelism, nil
}

// parallelismFromEnv returns the parallelism and where it came from.
func parallelismFromEnv() (int, string, error) {
	value := strings.TrimSpace(os.Getenv(parallelismEnvVar))
	if value == "" {
		return maxParallelImages, "default", nil
	}
	parallelism, err := parseParallelism(value)
	if err != nil {
		return 0, "", fmt.Errorf("%s=%s: %w", parallelismEnvVar, value, err)
	}
	return parallelism, parallelismEnvVar, nil
}

// version returns the module version, which for a build from a checkout names
// the commit (+dirty with uncommitted changes).
func version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	return info.Main.Version
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	logger := slog.New(slog.NewTextHandler(stderr, nil))

	opts, err := parseFlags(args, stderr)
	if errors.Is(err, pflag.ErrHelp) {
		return exitPatched
	}
	if err != nil {
		logger.ErrorContext(ctx, "invalid command line", "error", err, "help", "emudhra-checker --help")
		return exitUsage
	}
	parallelismSource := "--parallel"
	if !opts.parallelismSet {
		opts.parallelism, parallelismSource, err = parallelismFromEnv()
		if err != nil {
			logger.ErrorContext(ctx, "invalid configuration", "error", err)
			return exitConfigError
		}
	}
	logger.InfoContext(ctx, "starting",
		"version", version(),
		"go", runtime.Version(),
		"parallelism", opts.parallelism,
		"parallelism_from", parallelismSource,
		"local", opts.local,
	)

	targets, err := inventory.Read(opts.images, opts.imageFiles)
	if err != nil {
		logger.ErrorContext(ctx, "cannot read input", "error", err)
		return exitConfigError
	}
	if len(targets) == 0 {
		logger.ErrorContext(ctx, "nothing to scan: provide image references or --image-file",
			"help", "emudhra-checker --help")
		return exitUsage
	}

	certificates, err := certdb.Load(opts.certificateFile)
	if err != nil {
		logger.ErrorContext(ctx, "cannot load certificate database", "error", err)
		return exitConfigError
	}

	// One scan serves every row naming the image, so the log names only the image.
	var scanned atomic.Int64
	tracker := newProgress(logger)
	stopProgress := make(chan struct{})
	var progressDone sync.WaitGroup
	progressDone.Go(func() { tracker.run(ctx, progressInterval, stopProgress) })
	results := scan.Targets(ctx, targets, opts.parallelism, func(target inventory.ImageTarget) scan.ImageResult {
		scanned.Add(1)
		start := tracker.start(target.Image)
		logger.InfoContext(ctx, "scanning image", "image", target.Image)
		result := scan.Image(ctx, target, certificates, opts.local)
		tracker.finish(target.Image)
		duration := time.Since(start).Round(durationPrecision)
		switch {
		case ctx.Err() != nil:
			// Interrupted: the summary below says so once.
		case result.Failed():
			logger.ErrorContext(ctx, "could not check image",
				"status", result.Status, "image", target.Image, "duration", duration, "error", result.Error)
		default:
			logger.InfoContext(ctx, "scanned image",
				"status", result.Status, "image", target.Image, "duration", duration)
		}
		return result
	})
	close(stopProgress)
	progressDone.Wait()
	if ctx.Err() != nil {
		logger.WarnContext(ctx, "interrupted, no report written", "images_started", scanned.Load())
		return exitInterrupted
	}
	logger.InfoContext(ctx, "finished", "rows", len(results), "images", scanned.Load())

	report.Sort(results)
	switch opts.output {
	case outputJSON:
		err = report.WriteJSON(stdout, results)
	case outputCSV:
		err = report.WriteCSV(stdout, results)
	default:
		report.WriteTable(stdout, results)
	}
	if err != nil {
		logger.ErrorContext(ctx, "cannot write report", "error", err)
		return exitConfigError
	}
	return exitCode(results)
}

// exitCode ranks failed scans (UNKNOWN, ERR_DOCKER_PULL) over VULNERABLE and
// PARTIALLY_MITIGATED over PATCHED and MITIGATED.
func exitCode(results []scan.ImageResult) int {
	code := exitPatched
	for _, result := range results {
		if result.Failed() {
			return exitUnknown
		}
		if result.Status == scan.StatusVulnerable || result.Status == scan.StatusPartiallyMitigated {
			code = exitVulnerable
		}
	}
	return code
}
