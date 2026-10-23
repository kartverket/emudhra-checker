package scan

import (
	"os"
	"runtime"
	"testing"
)

// testBinary returns the running test executable, a real Go binary.
func testBinary(t *testing.T) []byte {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestGoBinaryVersion(t *testing.T) {
	t.Parallel()
	got, ok := goBinaryVersion(testBinary(t))
	if !ok || got != runtime.Version() {
		t.Errorf("goBinaryVersion(test binary) = %q, %t; want %q", got, ok, runtime.Version())
	}
	if _, isGo := goBinaryVersion([]byte("#!/bin/sh\necho not a Go binary\n")); isGo {
		t.Error("goBinaryVersion found a Go version in a shell script")
	}
}

func TestGoVersionStatus(t *testing.T) {
	t.Parallel()
	tests := []struct {
		version string
		want    string
	}{
		{"go1.27.3", VersionFixed},
		{"go1.27.10", VersionFixed},
		{"go1.27.2", VersionOutdated},
		{"go1.27rc1", VersionOutdated},
		{"go1.26.10", VersionFixed},
		{"go1.26.9", VersionOutdated},
		{"go1.25.12", VersionOutdated},
		{"go1.28", VersionFixed},
		{"go1.28.1", VersionFixed},
		{"go1.27.3 X:boringcrypto", VersionFixed},
		{"devel go1.28-abcdef Mon Oct 19 2026", VersionUnknown},
		{"", VersionUnknown},
	}
	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			t.Parallel()
			if got, _ := goScheme().status(test.version); got != test.want {
				t.Errorf("versionStatus(go, %q) = %s, want %s", test.version, got, test.want)
			}
		})
	}
}
