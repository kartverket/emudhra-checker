package main

import (
	"context"
	"log/slog"
	"net/http/httptest"

	"bytes"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	memregistry "github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kartverket/emudhra-checker/internal/scan"
)

func TestParseParallelism(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{"minimum", "1", true},
		{"maximum", "10", true},
		{"zero", "0", false},
		{"above maximum", "11", false},
		{"not a number", "many", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseParallelism(test.value)
			if (err == nil) != test.valid {
				t.Errorf("parseParallelism(%q) error = %v, want valid=%t", test.value, err, test.valid)
			}
		})
	}
}

// TestRun covers the paths that stop before any registry is contacted.
func TestRun(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
	}{
		{"help lists each flag once with its alias", []string{"--help"}, exitPatched, "-f, --image-file FILE"},
		{"unknown output format", []string{"-o", "xml", "nginx"}, exitUsage, "must be table, json or csv"},
		{"unknown flag", []string{"--image", "x"}, exitUsage, `msg="invalid command line"`},
		{"parallel out of range", []string{"--parallel", "11", "nginx"}, exitUsage, "must be between 1 and 10"},
		{"no images", nil, exitUsage, "provide image references"},
		{"missing input file", []string{"-f", "does-not-exist.csv"}, exitConfigError, `msg="cannot read input"`},
		{
			"missing certificate database",
			[]string{"-c", "does-not-exist.json", "nginx"},
			exitConfigError,
			`msg="cannot load certificate database"`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			code := run(t.Context(), test.args, &stdout, &stderr)
			if code != test.wantCode {
				t.Errorf("exit code = %d, want %d", code, test.wantCode)
			}
			if !strings.Contains(stderr.String(), test.wantErr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), test.wantErr)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want nothing", stdout.String())
			}
		})
	}
}

func TestExitCode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		statuses []string
		want     int
	}{
		{"all patched", []string{scan.StatusPatched, scan.StatusPatched}, exitPatched},
		{"vulnerable", []string{scan.StatusPatched, scan.StatusVulnerable}, exitVulnerable},
		{"mitigated passes", []string{scan.StatusPatched, scan.StatusMitigated}, exitPatched},
		{"partially mitigated fails", []string{scan.StatusMitigated, scan.StatusPartiallyMitigated}, exitVulnerable},
		{
			"unknown wins over vulnerable",
			[]string{scan.StatusVulnerable, scan.StatusUnknown, scan.StatusVulnerable},
			exitUnknown,
		},
		{"pull error counts as unknown", []string{scan.StatusVulnerable, scan.StatusPullError}, exitUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			results := make([]scan.ImageResult, 0, len(test.statuses))
			for _, status := range test.statuses {
				results = append(results, scan.ImageResult{Status: status})
			}
			if got := exitCode(results); got != test.want {
				t.Errorf("exitCode(%v) = %d, want %d", test.statuses, got, test.want)
			}
		})
	}
}

// TestRunReportsPullErrors pulls a tag that does not exist from an in-memory registry.
func TestRunReportsPullErrors(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(
		memregistry.New(memregistry.Logger(slog.NewLogLogger(slog.DiscardHandler, slog.LevelError))),
	)
	t.Cleanup(server.Close)
	image := strings.TrimPrefix(server.URL, "http://") + "/team/app:missing"
	present := strings.TrimPrefix(server.URL, "http://") + "/team/app:present"
	ref, err := name.ParseReference(present)
	if err != nil {
		t.Fatal(err)
	}
	randomImage, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err = remote.Write(ref, randomImage); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{"-o", "csv", "--parallel", "2", image, present}, &stdout, &stderr)
	if code != exitUnknown {
		t.Errorf("exit code = %d, want %d", code, exitUnknown)
	}
	first, _, _ := strings.Cut(stderr.String(), "\n")
	for _, want := range []string{"level=INFO msg=starting version=", " go=go1.", " parallelism=2 parallelism_from=--parallel"} {
		if !strings.Contains(first, want) {
			t.Errorf("first stderr line = %q, want it to contain %q", first, want)
		}
	}
	for _, want := range []string{
		`level=ERROR msg="could not check image" status=ERR_DOCKER_PULL image=` + image,
		`error="cannot pull image: fetch manifest:`,
		`level=INFO msg="scanned image" status=PATCHED image=` + present + " duration=",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
		}
	}
	if !strings.Contains(stdout.String(), ","+image+",ERR_DOCKER_PULL,") {
		t.Errorf("stdout = %q, want an ERR_DOCKER_PULL row for %s", stdout.String(), image)
	}
}

// TestRunInterrupted covers Ctrl+C before any scan starts.
func TestRunInterrupted(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	var stdout, stderr bytes.Buffer
	if code := run(ctx, []string{"nginx", "alpine"}, &stdout, &stderr); code != exitInterrupted {
		t.Errorf("exit code = %d, want %d", code, exitInterrupted)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want no report", stdout.String())
	}
	if want := `msg="interrupted, no report written" images_started=0`; !strings.Contains(stderr.String(), want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
	}
	if strings.Contains(stderr.String(), "scanning image") {
		t.Errorf("stderr = %q, want no scans after the interrupt", stderr.String())
	}
}
