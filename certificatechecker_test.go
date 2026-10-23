package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func makeTestLayer(t *testing.T, files map[string][]byte) ([]byte, string) {
	t.Helper()

	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	for name, content := range files {
		header := &tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(buffer.Bytes())
	return buffer.Bytes(), "sha256:" + hex.EncodeToString(sum[:])
}

func TestParseImageReference(t *testing.T) {
	tests := []struct {
		image, registry, repository, reference string
	}{
		{"nginx:1.27", "registry-1.docker.io", "library/nginx", "1.27"},
		{"org/app:v2", "registry-1.docker.io", "org/app", "v2"},
		{"ghcr.io/org/app@sha256:abc", "ghcr.io", "org/app", "sha256:abc"},
	}
	for _, test := range tests {
		registry, repository, reference, err := parseImageReference(test.image)
		if err != nil {
			t.Fatalf("parseImageReference(%q): %v", test.image, err)
		}
		if registry != test.registry || repository != test.repository || reference != test.reference {
			t.Errorf(
				"parseImageReference(%q) = (%q, %q, %q), want (%q, %q, %q)",
				test.image,
				registry,
				repository,
				reference,
				test.registry,
				test.repository,
				test.reference,
			)
		}
	}
}

func TestImageJavaSettings(t *testing.T) {
	config := imageConfig{}
	config.Config.WorkingDir = "/app"
	config.Config.Env = []string{
		"JAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStore=conf/trust.p12",
	}
	config.Config.Entrypoint = []string{"java", "-jar", "service.jar"}

	stores, evidence, startup := imageJavaSettings(config)
	if !startup {
		t.Fatal("expected JVM startup to be detected")
	}
	if !stores["app/conf/trust.p12"] {
		t.Fatalf("configured trust store was not normalized: %#v", stores)
	}
	if len(evidence) != 2 {
		t.Fatalf("got %d evidence entries, want 2", len(evidence))
	}
}

func TestScanLayerMatchesAndRemovesCertificates(t *testing.T) {
	certificate := DistrustedCertificate{
		SHA256: "test-fingerprint",
		Kind:   "root",
		Name:   "Test Root",
		DER:    []byte("test-certificate-der"),
		PEM:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
	}
	filesystemFindings := make(map[string]Finding)
	javaTrustStores := make(map[string]JavaTrustStore)
	javaRuntimeFiles := make(map[string]string)
	configuredStores := map[string]bool{}
	storePath := "usr/lib/jvm/test/lib/security/cacerts"

	firstLayer, firstDigest := makeTestLayer(t, map[string][]byte{
		"usr/lib/jvm/test/bin/java": []byte("java runtime"),
		storePath:                   certificate.DER,
	})
	if err := scanLayer(
		bytes.NewReader(firstLayer),
		firstDigest,
		[]DistrustedCertificate{certificate},
		filesystemFindings,
		javaTrustStores,
		javaRuntimeFiles,
		configuredStores,
	); err != nil {
		t.Fatal(err)
	}
	if len(filesystemFindings) != 1 || len(javaTrustStores[storePath].Certificates) != 1 {
		t.Fatal("expected certificate finding in Java trust store")
	}
	if len(javaRuntimeFiles) != 1 {
		t.Fatal("expected JVM runtime file detection")
	}

	secondLayer, secondDigest := makeTestLayer(t, map[string][]byte{
		storePath: []byte("clean replacement"),
	})
	if err := scanLayer(
		bytes.NewReader(secondLayer),
		secondDigest,
		[]DistrustedCertificate{certificate},
		filesystemFindings,
		javaTrustStores,
		javaRuntimeFiles,
		configuredStores,
	); err != nil {
		t.Fatal(err)
	}
	if len(filesystemFindings) != 0 {
		t.Fatal("replacement layer should clear the old certificate finding")
	}
	if len(javaTrustStores[storePath].Certificates) != 0 {
		t.Fatal("replacement trust store should not retain old certificate")
	}

	whiteoutLayer, whiteoutDigest := makeTestLayer(t, map[string][]byte{
		"usr/lib/jvm/test/lib/security/.wh.cacerts": nil,
	})
	if err := scanLayer(
		bytes.NewReader(whiteoutLayer),
		whiteoutDigest,
		[]DistrustedCertificate{certificate},
		filesystemFindings,
		javaTrustStores,
		javaRuntimeFiles,
		configuredStores,
	); err != nil {
		t.Fatal(err)
	}
	if _, exists := javaTrustStores[storePath]; exists {
		t.Fatal("whiteout should remove the trust-store record")
	}
}

func TestReadTargetsCSV(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "images.csv")
	content := "namespace,application,image\n\"team,one\",service,ghcr.io/org/app:v1\n"
	if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	targets, err := readTargets(nil, filename)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("got %d targets, want 1", len(targets))
	}
	if targets[0].Namespace != "team,one" ||
		targets[0].Application != "service" ||
		targets[0].Image != "ghcr.io/org/app:v1" {
		t.Fatalf("unexpected parsed target: %#v", targets[0])
	}
}

func TestLoadCertificatesFromRepositoryDatabase(t *testing.T) {
	filename := defaultCertificatePath()
	certificates, err := loadCertificates(filename)
	if err != nil {
		t.Fatal(err)
	}
	if len(certificates) == 0 {
		t.Fatal("expected certificates in repository database")
	}
}

func TestScanTargetsLimitsConcurrencyAndPreservesOrder(t *testing.T) {
	targets := make([]ImageTarget, 12)
	for index := range targets {
		targets[index].Image = fmt.Sprintf("image-%d", index)
	}

	var active int32
	var maximum int32
	results := scanTargets(targets, 3, func(target ImageTarget) ImageResult {
		current := atomic.AddInt32(&active, 1)
		for {
			observed := atomic.LoadInt32(&maximum)
			if current <= observed || atomic.CompareAndSwapInt32(&maximum, observed, current) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		atomic.AddInt32(&active, -1)
		return ImageResult{Image: target.Image, Status: "PATCHED"}
	})

	if maximum > 3 {
		t.Fatalf("observed %d concurrent scans; limit was 3", maximum)
	}
	for index, result := range results {
		if result.Image != targets[index].Image {
			t.Errorf("result %d is for %q, want %q", index, result.Image, targets[index].Image)
		}
	}
}

func TestScanTargetsReusesSuccessfulDuplicateImageScans(t *testing.T) {
	targets := []ImageTarget{
		{Namespace: "ns-a", Application: "app-a", Image: "registry.example/shared:v1"},
		{Namespace: "ns-b", Application: "app-b", Image: "registry.example/shared:v1"},
		{Namespace: "ns-c", Application: "app-c", Image: "registry.example/shared:v1"},
	}
	var scans int32
	results := scanTargets(targets, 3, func(target ImageTarget) ImageResult {
		atomic.AddInt32(&scans, 1)
		time.Sleep(10 * time.Millisecond)
		return ImageResult{Image: target.Image, Status: "VULNERABLE"}
	})

	if got := atomic.LoadInt32(&scans); got != 1 {
		t.Fatalf("performed %d scans for duplicate image; want 1", got)
	}
	for index, result := range results {
		if result.Namespace != targets[index].Namespace ||
			result.Application != targets[index].Application ||
			result.Image != targets[index].Image ||
			result.Status != "VULNERABLE" {
			t.Errorf("result %d does not match its input target: %#v", index, result)
		}
	}
}

func TestScanTargetsDoesNotCacheUnknownResults(t *testing.T) {
	targets := []ImageTarget{
		{Image: "registry.example/temporary:v1"},
		{Image: "registry.example/temporary:v1"},
		{Image: "registry.example/temporary:v1"},
	}
	var scans int32
	results := scanTargets(targets, 3, func(target ImageTarget) ImageResult {
		atomic.AddInt32(&scans, 1)
		time.Sleep(5 * time.Millisecond)
		return ImageResult{Image: target.Image, Status: "UNKNOWN"}
	})

	if got := atomic.LoadInt32(&scans); got != int32(len(targets)) {
		t.Fatalf("performed %d scans for unknown results; want %d", got, len(targets))
	}
	for index, result := range results {
		if result.Status != "UNKNOWN" {
			t.Errorf("result %d has status %q; want UNKNOWN", index, result.Status)
		}
	}
}

func TestParseParallelism(t *testing.T) {
	for _, value := range []string{"1", "10"} {
		if _, err := parseParallelism(value); err != nil {
			t.Errorf("parseParallelism(%q): %v", value, err)
		}
	}
	for _, value := range []string{"0", "11", "many"} {
		if _, err := parseParallelism(value); err == nil {
			t.Errorf("parseParallelism(%q) unexpectedly succeeded", value)
		}
	}
}
