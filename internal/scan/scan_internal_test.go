package scan

import (
	"bytes"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kartverket/emudhra-checker/internal/certdb"
	"github.com/kartverket/emudhra-checker/internal/inventory"

	"github.com/google/go-containerregistry/pkg/name"
	memregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

func testImage(t *testing.T, files map[string][]byte, config v1.Config) v1.Image {
	t.Helper()
	data, _ := makeTestLayer(t, files)
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	image, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	image, err = mutate.Config(image, config)
	if err != nil {
		t.Fatal(err)
	}
	return image
}

func checkImageResult(t *testing.T, result ImageResult, status, bundle string) {
	t.Helper()
	if result.Status != status {
		t.Fatalf("status = %s (error %q), want %s", result.Status, result.Error, status)
	}
	if result.Failed() != (result.Error != "") {
		t.Errorf("failed = %t but error = %q", result.Failed(), result.Error)
	}
	if status == StatusVulnerable &&
		(len(result.Findings) != 1 || result.Findings[0].Path != bundle || !result.JVMDetected) {
		t.Errorf("want one finding in %s and a JVM, got %+v", bundle, result)
	}
}

// TestImage scans images pushed to an in-memory registry.
func TestImage(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(
		memregistry.New(memregistry.Logger(slog.NewLogLogger(slog.DiscardHandler, slog.LevelError))),
	)
	t.Cleanup(server.Close)
	host := strings.TrimPrefix(server.URL, "http://")

	certificates, err := certdb.Load("")
	if err != nil {
		t.Fatal(err)
	}
	bundle := "etc/ssl/certs/ca-certificates.crt"
	vulnerable := testImage(t, map[string][]byte{
		bundle:              []byte(certificates[0].PEM + "\n"),
		"opt/java/bin/java": []byte("jvm"),
	}, v1.Config{Entrypoint: []string{"java", "-jar", "app.jar"}})
	complete, canonical := blockedCertsFiles(t, certificates)
	blocked := func(list string) v1.Image {
		return testImage(t, map[string][]byte{
			bundle:                                []byte(certificates[0].PEM + "\n"),
			"opt/java/lib/security/blocked.certs": []byte(list),
		}, v1.Config{})
	}
	mitigated, partiallyMitigated := blocked(complete), blocked(canonical)
	clean := testImage(t, map[string][]byte{bundle: []byte("no distrusted roots\n")}, v1.Config{})
	blocklisted := testImage(t, map[string][]byte{
		"etc/pki/ca-trust/source/blocklist/emsign.pem": []byte(certificates[0].PEM + "\n"),
	}, v1.Config{})
	garbage, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("not a tar archive")), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	unreadable, err := mutate.AppendLayers(empty.Image, garbage)
	if err != nil {
		t.Fatal(err)
	}
	index := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: clean, Platform: &v1.Platform{OS: "linux", Architecture: "arm64"}},
		mutate.IndexAddendum{Add: vulnerable, Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}},
	)

	push := func(tag string, write func(name.Reference) error) string {
		t.Helper()
		ref, parseErr := name.ParseReference(host + "/team/app:" + tag)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		if writeErr := write(ref); writeErr != nil {
			t.Fatal(writeErr)
		}
		return ref.String()
	}
	tests := []struct {
		name, image, status string
	}{
		{"vulnerable image", push("vulnerable", func(ref name.Reference) error {
			return remote.Write(ref, vulnerable)
		}), StatusVulnerable},
		{"clean image", push("clean", func(ref name.Reference) error {
			return remote.Write(ref, clean)
		}), StatusPatched},
		{"index resolves to linux/amd64", push("multi-platform", func(ref name.Reference) error {
			return remote.WriteIndex(ref, index)
		}), StatusVulnerable},
		{"jdk blocks every encoding", push("mitigated", func(ref name.Reference) error {
			return remote.Write(ref, mitigated)
		}), StatusMitigated},
		{"jdk blocks only canonical fingerprints", push("partially-mitigated", func(ref name.Reference) error {
			return remote.Write(ref, partiallyMitigated)
		}), StatusPartiallyMitigated},
		{"root only in a p11-kit blocklist", push("blocklisted", func(ref name.Reference) error {
			return remote.Write(ref, blocklisted)
		}), StatusPatched},
		{"unreadable layer", push("unreadable", func(ref name.Reference) error {
			return remote.Write(ref, unreadable)
		}), StatusUnknown},
		{"missing tag", host + "/team/app:missing", StatusPullError},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			checkImageResult(
				t,
				Image(t.Context(), inventory.ImageTarget{Image: test.image}, certificates, false),
				test.status,
				bundle,
			)
		})
	}
}

// TestLocalImage scans images that a stand-in docker CLI exports.
func TestLocalImage(t *testing.T) {
	certificates, err := certdb.Load("")
	if err != nil {
		t.Fatal(err)
	}
	bundle := "etc/ssl/certs/ca-certificates.crt"
	image := testImage(t, map[string][]byte{
		bundle:              []byte(certificates[0].PEM + "\n"),
		"opt/java/bin/java": []byte("jvm"),
	}, v1.Config{})
	bin, exports := t.TempDir(), t.TempDir()
	export := filepath.Join(bin, "app.tar")
	err = tarball.WriteToFile(export, name.MustParseReference("app:dev").(name.Tag), image)
	if err != nil {
		t.Fatal(err)
	}
	// $4 is the reference in: docker image save -- REFERENCE
	script := "#!/bin/sh\n[ \"$4\" = app:dev ] && exec cat " + export + "\n" +
		"echo \"Error response from daemon: No such image: $4\" >&2\nexit 1\n"
	err = os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o700)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("TMPDIR", exports)

	scanLocal := func(reference string) ImageResult {
		return Image(t.Context(), inventory.ImageTarget{Image: reference}, certificates, true)
	}
	checkImageResult(t, scanLocal("app:dev"), StatusVulnerable, bundle)
	missing := scanLocal("app:gone")
	checkImageResult(t, missing, StatusPullError, bundle)
	if !strings.Contains(missing.Error, "No such image: app:gone") {
		t.Errorf("error = %q, want the message from docker", missing.Error)
	}
	if left, _ := os.ReadDir(exports); len(left) > 0 {
		t.Errorf("export files left behind: %v", left)
	}
}
