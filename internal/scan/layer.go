package scan

import (
	"archive/tar"
	"bufio"
	"cmp"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/kartverket/emudhra-checker/internal/certdb"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/klauspost/compress/zstd"
)

const (
	gzipMagic = "\x1f\x8b"
	zstdMagic = "\x28\xb5\x2f\xfd"
)

// fileEntry is one entry of a layer, as detectors see it. data, fileSHA256 and
// certificates are set only for regular files.
type fileEntry struct {
	path         string
	layerDigest  string
	regular      bool
	data         []byte
	fileSHA256   string
	certificates []certdb.CertificateMatch
}

// evidence is one thing that a detector found, in a file or in the image
// config. Each value sets one field.
type evidence struct {
	finding    *Finding
	trustStore *JavaTrustStore
	component  *Component
	jvm        string // a reason to think that the image runs a JVM
	caConf     []byte // the content of /etc/ca-certificates.conf
}

// imageScan applies the layers of an image in order. For each path of the
// final filesystem, it keeps what the detectors found in the file at that
// path. A file that a later layer deletes or replaces loses its evidence.
type imageScan struct {
	certificates []certdb.DistrustedCertificate
	detectors    []detector
	evidence     map[string][]evidence
}

func newImageScan(config v1.Config, certificates []certdb.DistrustedCertificate) *imageScan {
	return &imageScan{
		certificates: certificates,
		detectors:    detectorsFor(config, certificates),
		evidence:     make(map[string][]evidence),
	}
}

// whiteout returns a matcher for the paths a whiteout entry deletes, or nil
// for an ordinary file.
func whiteout(filename string) func(string) bool {
	parent, base := path.Split(filename)
	if base == ".wh..wh..opq" {
		return func(existing string) bool { return strings.HasPrefix(existing, parent) }
	}
	if deleted, ok := strings.CutPrefix(base, ".wh."); ok {
		deletedPath := parent + deleted
		return func(existing string) bool {
			return existing == deletedPath || strings.HasPrefix(existing, deletedPath+"/")
		}
	}
	return nil
}

func deletePaths[T any](records map[string]T, match func(string) bool) {
	maps.DeleteFunc(records, func(filename string, _ T) bool { return match(filename) })
}

// scanImageLayer reads a layer as the registry stores it, checked against its
// digest. With uncompressed, it reads the layer tar, checked against its diff
// ID: docker image save usually writes uncompressed layers, and their digest
// would mean compressing them again.
func (s *imageScan) scanImageLayer(layer v1.Layer, uncompressed bool) error {
	digestOf, open := layer.Digest, layer.Compressed
	if uncompressed {
		digestOf, open = layer.DiffID, layer.Uncompressed
	}
	digest, err := digestOf()
	if err != nil {
		return fmt.Errorf("read layer digest: %w", err)
	}
	blob, err := open()
	if err != nil {
		return fmt.Errorf("%w: fetch layer %s: %w", errPull, digest, err)
	}
	defer blob.Close()
	return s.scanLayer(blob, digest.String())
}

// verifyDigest checks a computed SHA-256 sum against an OCI digest.
func verifyDigest(sum []byte, digest string) error {
	algorithm, expected, found := strings.Cut(digest, ":")
	if !found || algorithm != "sha256" {
		return fmt.Errorf("unsupported digest %q", digest)
	}
	if actual := hex.EncodeToString(sum); actual != expected {
		return fmt.Errorf("digest mismatch: expected %s, got sha256:%s", digest, actual)
	}
	return nil
}

func (s *imageScan) scanLayer(stream io.Reader, layerDigest string) error {
	hasher := sha256.New()
	buffered := bufio.NewReader(io.TeeReader(stream, hasher))
	var layer io.Reader = buffered
	magic, _ := buffered.Peek(len(zstdMagic))
	switch {
	case strings.HasPrefix(string(magic), gzipMagic):
		gzipReader, err := gzip.NewReader(buffered)
		if err != nil {
			return fmt.Errorf("open gzip layer: %w", err)
		}
		layer = gzipReader
	case string(magic) == zstdMagic:
		zstdReader, err := zstd.NewReader(buffered, zstd.WithDecoderConcurrency(1))
		if err != nil {
			return fmt.Errorf("open zstd layer: %w", err)
		}
		defer zstdReader.Close()
		layer = zstdReader
	}

	tarReader := tar.NewReader(layer)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read image layer tar: %w", err)
		}
		err = s.addEntry(header, tarReader, layerDigest)
		if err != nil {
			return err
		}
	}

	// The digest covers the whole blob, including what the tar reader did not need.
	_, err := io.Copy(io.Discard, layer)
	if err != nil {
		return fmt.Errorf("finish image layer: %w", err)
	}
	return verifyDigest(hasher.Sum(nil), layerDigest)
}

func (s *imageScan) addEntry(header *tar.Header, content io.Reader, layerDigest string) error {
	filename := strings.TrimPrefix(path.Clean("/"+header.Name), "/")
	if filename == "" {
		return nil
	}
	if deleted := whiteout(filename); deleted != nil {
		deletePaths(s.evidence, deleted)
		return nil
	}

	// Replacing a path in a later layer invalidates its earlier evidence.
	delete(s.evidence, filename)

	entry := fileEntry{path: filename, layerDigest: layerDigest}
	if header.Typeflag == tar.TypeReg {
		data, err := io.ReadAll(content)
		if err != nil {
			return fmt.Errorf("read image file %s: %w", filename, err)
		}
		sum := sha256.Sum256(data)
		entry.regular = true
		entry.data = data
		entry.fileSHA256 = hex.EncodeToString(sum[:])
		entry.certificates = certdb.Find(data, s.certificates)
	}

	var found []evidence
	for _, detector := range s.detectors {
		found = append(found, detector.entry(entry)...)
	}
	if len(found) > 0 {
		s.evidence[filename] = found
	}
	return nil
}

// configEvidence returns what the detectors found in the image config.
func (s *imageScan) configEvidence() []evidence {
	var found []evidence
	for _, detector := range s.detectors {
		found = append(found, detector.image...)
	}
	return found
}

// collected is the evidence of an image, sorted by kind.
type collected struct {
	findings    []Finding
	trustStores []JavaTrustStore
	components  []Component
	jvm         []string
	caConf      []byte
}

// collect gathers the evidence from the image config and from the final
// filesystem. Findings, trust stores and components are sorted by path, and
// components with the same path by kind.
func (s *imageScan) collect() collected {
	var result collected
	add := func(found evidence) {
		switch {
		case found.finding != nil:
			result.findings = append(result.findings, *found.finding)
		case found.trustStore != nil:
			result.trustStores = append(result.trustStores, *found.trustStore)
		case found.component != nil:
			result.components = append(result.components, *found.component)
		case found.jvm != "":
			result.jvm = append(result.jvm, found.jvm)
		case found.caConf != nil:
			result.caConf = found.caConf
		}
	}
	for _, found := range s.configEvidence() {
		add(found)
	}
	for _, file := range slices.Sorted(maps.Keys(s.evidence)) {
		for _, found := range s.evidence[file] {
			add(found)
		}
	}
	slices.SortStableFunc(result.components, func(a, b Component) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Kind, b.Kind))
	})
	return result
}
