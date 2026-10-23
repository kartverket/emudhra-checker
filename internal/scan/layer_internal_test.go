package scan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"runtime"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/kartverket/emudhra-checker/internal/certdb"

	"github.com/klauspost/compress/zstd"
)

func makeTestTar(t *testing.T, files map[string][]byte) []byte {
	t.Helper()

	var buffer bytes.Buffer
	tarWriter := tar.NewWriter(&buffer)
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
	return buffer.Bytes()
}

func layerDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// makeTestLayer returns a gzip-compressed layer and its digest.
func makeTestLayer(t *testing.T, files map[string][]byte) ([]byte, string) {
	t.Helper()
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	if _, err := gzipWriter.Write(makeTestTar(t, files)); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes(), layerDigest(buffer.Bytes())
}

func TestVerifyDigest(t *testing.T) {
	t.Parallel()
	sum := sha256.Sum256([]byte("blob"))
	if err := verifyDigest(sum[:], "sha256:"+hex.EncodeToString(sum[:])); err != nil {
		t.Errorf("verifyDigest rejected the right digest: %v", err)
	}
	if err := verifyDigest(sum[:], "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Error("verifyDigest accepted a wrong digest")
	}
	if err := verifyDigest(sum[:], "md5:abc"); err == nil {
		t.Error("verifyDigest accepted an unsupported algorithm")
	}
}

func TestImageScan_ScanLayerCompression(t *testing.T) {
	t.Parallel()
	certificate := certdb.DistrustedCertificate{SHA256: "fp", Name: "Test Root", DER: []byte("test-certificate-der")}
	archive := makeTestTar(t, map[string][]byte{"etc/ssl/cert.pem": certificate.DER})
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	zstdLayer := encoder.EncodeAll(archive, nil)
	err = encoder.Close()
	if err != nil {
		t.Fatal(err)
	}
	gzipLayer, _ := makeTestLayer(t, map[string][]byte{"etc/ssl/cert.pem": certificate.DER})

	for _, test := range []struct {
		name  string
		layer []byte
	}{
		{"gzip", gzipLayer},
		{"zstd", zstdLayer},
		{"uncompressed", archive},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			scan := newImageScan(v1.Config{}, []certdb.DistrustedCertificate{certificate})
			scanErr := scan.scanLayer(bytes.NewReader(test.layer), layerDigest(test.layer))
			if scanErr != nil {
				t.Fatal(scanErr)
			}
			if len(scan.collect().findings) != 1 {
				t.Fatal("certificate not found in layer")
			}
		})
	}
}

func TestImageScan_GoBinaries(t *testing.T) {
	t.Parallel()
	scan := newImageScan(v1.Config{}, nil)
	applyLayer := func(files map[string][]byte) {
		t.Helper()
		layer := makeTestTar(t, files)
		if err := scan.scanLayer(bytes.NewReader(layer), layerDigest(layer)); err != nil {
			t.Fatal(err)
		}
	}

	applyLayer(map[string][]byte{"app/server": testBinary(t), "app/run.sh": []byte("#!/bin/sh\n")})
	binary := componentOf(scan, "app/server", KindGo)
	if len(scan.collect().components) != 1 || binary.Version != runtime.Version() || binary.Status != VersionFixed {
		t.Fatalf("want app/server built with %s, got %#v", runtime.Version(), scan.collect().components)
	}

	applyLayer(map[string][]byte{"app/.wh.server": nil})
	if len(scan.collect().components) != 0 {
		t.Fatal("whiteout should remove the Go binary")
	}
}

func TestImageScan_ScanLayer(t *testing.T) {
	t.Parallel()
	certificate := certdb.DistrustedCertificate{
		SHA256: "test-fingerprint",
		Kind:   "root",
		Name:   "Test Root",
		DER:    []byte("test-certificate-der"),
		PEM:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
	}
	scan := newImageScan(v1.Config{}, []certdb.DistrustedCertificate{certificate})
	storePath := "usr/lib/jvm/test/lib/security/cacerts"
	applyLayer := func(files map[string][]byte) {
		t.Helper()
		layer, digest := makeTestLayer(t, files)
		if err := scan.scanLayer(bytes.NewReader(layer), digest); err != nil {
			t.Fatal(err)
		}
	}

	applyLayer(map[string][]byte{
		"./usr/lib/jvm/test/bin/java": []byte("java runtime"),
		storePath:                     certificate.DER,
	})
	if len(scan.collect().findings) != 1 || len(trustStoreAt(scan, storePath).Certificates) != 1 {
		t.Fatal("expected certificate finding in Java trust store")
	}
	if len(scan.collect().jvm) != 1 {
		t.Fatal("expected JVM runtime file detection")
	}

	applyLayer(map[string][]byte{storePath: []byte("clean replacement")})
	if len(scan.collect().findings) != 0 {
		t.Fatal("replacement layer should clear the old certificate finding")
	}
	if len(trustStoreAt(scan, storePath).Certificates) != 0 {
		t.Fatal("replacement trust store should not retain old certificate")
	}

	applyLayer(map[string][]byte{"usr/lib/jvm/test/lib/security/.wh.cacerts": nil})
	if len(scan.collect().trustStores) != 0 {
		t.Fatal("whiteout should remove the trust-store record")
	}

	applyLayer(map[string][]byte{"./.wh.usr": nil})
	if len(scan.collect().jvm) != 0 {
		t.Fatal("root-level whiteout should remove everything below it")
	}

	layer, _ := makeTestLayer(t, map[string][]byte{"file": nil})
	if err := scan.scanLayer(bytes.NewReader(layer), "sha256:00"); err == nil {
		t.Fatal("scanLayer accepted a layer with the wrong digest")
	}
}
