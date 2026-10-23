package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const manifestAccept = "application/vnd.oci.image.index.v1+json, " +
	"application/vnd.oci.image.manifest.v1+json, " +
	"application/vnd.docker.distribution.manifest.list.v2+json, " +
	"application/vnd.docker.distribution.manifest.v2+json, " +
	"application/json"

const userAgent = "emudhra-checker-image-scanner/1.0"
const maxParallelImages = 10
const parallelismEnvVar = "CERTIFICATECHECKER_PARALLELISM"

var (
	pemCertificateRE       = regexp.MustCompile(`(?s)-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----`)
	trustStorePropertyRE   = regexp.MustCompile(`-Djavax\.net\.ssl\.trustStore=([^\s"']+)`)
	javaStartupRE          = regexp.MustCompile(`(?i)(^|[/\s])java(?:w)?(?:\.exe)?($|[\s])`)
	bearerChallengeValueRE = regexp.MustCompile(`(\w+)="([^"]*)"`)
	defaultTrustStoreNames = map[string]bool{"cacerts": true, "jssecacerts": true}
)

type DistrustedCertificate struct {
	SHA256 string `json:"sha256"`
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	PEM    string `json:"pem"`
	DER    []byte `json:"-"`
}

type ImageTarget struct {
	Namespace   string
	Application string
	Image       string
}

type CertificateMatch struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
}

type Finding struct {
	Path         string             `json:"path"`
	LayerDigest  string             `json:"layer_digest"`
	FileSHA256   string             `json:"file_sha256"`
	Certificates []CertificateMatch `json:"certificates"`
}

type JavaTrustStore struct {
	Path         string             `json:"path"`
	LayerDigest  string             `json:"layer_digest"`
	FileSHA256   string             `json:"file_sha256"`
	Certificates []CertificateMatch `json:"certificates"`
}

type ImageResult struct {
	Image           string           `json:"image"`
	Status          string           `json:"status"`
	Findings        []Finding        `json:"findings"`
	Namespace       string           `json:"namespace"`
	Application     string           `json:"application"`
	JVMDetected     bool             `json:"jvm_detected"`
	JVMEvidence     []string         `json:"jvm_evidence"`
	JavaTrustStores []JavaTrustStore `json:"java_truststores"`
	Error           string           `json:"error,omitempty"`
}

type manifestDescriptor struct {
	Digest   string `json:"digest"`
	Platform struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	} `json:"platform"`
}

type imageManifest struct {
	Manifests []manifestDescriptor `json:"manifests"`
	Config    struct {
		Digest string `json:"digest"`
	} `json:"config"`
	Layers []struct {
		Digest string `json:"digest"`
	} `json:"layers"`
}

type imageConfig struct {
	Config struct {
		Env        []string `json:"Env"`
		Entrypoint []string `json:"Entrypoint"`
		Cmd        []string `json:"Cmd"`
		WorkingDir string   `json:"WorkingDir"`
	} `json:"config"`
}

type registryClient struct {
	registry string
	user     string
	password string
	token    string
	http     *http.Client
}

func newRegistryClient(registry string) *registryClient {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DisableCompression:    true,
			ResponseHeaderTimeout: 60 * time.Second,
		},
	}
	r := &registryClient{registry: registry, http: client}
	if strings.EqualFold(registry, "ghcr.io") ||
		strings.EqualFold(registry, "docker.pkg.github.com") {
		r.user = firstNonEmpty(os.Getenv("GHCR_USERNAME"), os.Getenv("GITHUB_ACTOR"))
		r.password = firstNonEmpty(os.Getenv("GHCR_TOKEN"), os.Getenv("GITHUB_TOKEN"))
	}
	return r
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func (c *registryClient) endpoint(requestPath string) string {
	return (&url.URL{Scheme: "https", Host: c.registry, Path: requestPath}).String()
}

func (c *registryClient) do(method, requestPath, accept string, retryAuth bool) (*http.Response, error) {
	request, err := http.NewRequest(method, c.endpoint(requestPath), nil)
	if err != nil {
		return nil, fmt.Errorf("build registry request: %w", err)
	}
	request.Header.Set("User-Agent", userAgent)
	if accept == "" {
		accept = "*/*"
	}
	request.Header.Set("Accept", accept)

	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	} else if c.user != "" && c.password != "" {
		request.SetBasicAuth(c.user, c.password)
	}

	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s %s failed: %w", method, c.endpoint(requestPath), err)
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return response, nil
	}

	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized && retryAuth {
		challenge := response.Header.Get("WWW-Authenticate")
		if strings.HasPrefix(strings.ToLower(challenge), "bearer ") {
			if err := c.authenticateBearer(challenge); err != nil {
				return nil, err
			}
			return c.do(method, requestPath, accept, false)
		}
	}
	return nil, fmt.Errorf(
		"%s %s returned HTTP %d: %s",
		method,
		c.endpoint(requestPath),
		response.StatusCode,
		truncate(string(body), 300),
	)
}

func truncate(value string, max int) string {
	if len(value) > max {
		return value[:max]
	}
	return value
}

func (c *registryClient) authenticateBearer(challenge string) error {
	values := make(map[string]string)
	for _, match := range bearerChallengeValueRE.FindAllStringSubmatch(challenge, -1) {
		values[match[1]] = match[2]
	}
	realm := values["realm"]
	if realm == "" {
		return fmt.Errorf("registry requested bearer auth without a realm")
	}

	tokenURL, err := url.Parse(realm)
	if err != nil {
		return fmt.Errorf("invalid bearer token realm: %w", err)
	}
	query := tokenURL.Query()
	if values["service"] != "" {
		query.Set("service", values["service"])
	}
	if values["scope"] != "" {
		query.Set("scope", values["scope"])
	}
	tokenURL.RawQuery = query.Encode()

	request, err := http.NewRequest(http.MethodGet, tokenURL.String(), nil)
	if err != nil {
		return fmt.Errorf("build bearer token request: %w", err)
	}
	request.Header.Set("User-Agent", userAgent)
	if c.user != "" && c.password != "" {
		request.SetBasicAuth(c.user, c.password)
	}

	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("could not obtain registry bearer token: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf(
			"bearer token endpoint returned HTTP %d: %s",
			response.StatusCode,
			truncate(string(body), 300),
		)
	}

	var tokenResponse struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&tokenResponse); err != nil {
		return fmt.Errorf("invalid registry bearer token response: %w", err)
	}
	c.token = firstNonEmpty(tokenResponse.Token, tokenResponse.AccessToken)
	if c.token == "" {
		return fmt.Errorf("registry bearer token response contained no token")
	}
	return nil
}

func (c *registryClient) getJSON(requestPath, accept string, destination any) error {
	response, err := c.do(http.MethodGet, requestPath, accept, true)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if err := json.NewDecoder(response.Body).Decode(destination); err != nil {
		return fmt.Errorf("invalid JSON returned by registry: %w", err)
	}
	return nil
}

func (c *registryClient) getBlob(repository, digest string) ([]byte, error) {
	response, err := c.do(
		http.MethodGet,
		fmt.Sprintf("/v2/%s/blobs/%s", repository, digest),
		"",
		true,
	)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("read registry blob %s: %w", digest, err)
	}
	return data, nil
}

func (c *registryClient) openBlob(repository, digest string) (io.ReadCloser, error) {
	response, err := c.do(
		http.MethodGet,
		fmt.Sprintf("/v2/%s/blobs/%s", repository, digest),
		"",
		true,
	)
	if err != nil {
		return nil, err
	}
	return response.Body, nil
}

func parseImageReference(image string) (registry, repository, reference string, err error) {
	image = strings.TrimSpace(image)
	if image == "" {
		return "", "", "", fmt.Errorf("empty image reference")
	}

	first, remainder, found := strings.Cut(image, "/")
	if !found || (!strings.ContainsAny(first, ".:") && first != "localhost") {
		registry = "registry-1.docker.io"
		remainder = image
	} else {
		registry = first
	}

	if before, after, found := strings.Cut(remainder, "@sha256:"); found {
		repository = before
		reference = "sha256:" + after
	} else {
		lastSlash := strings.LastIndex(remainder, "/")
		lastColon := strings.LastIndex(remainder, ":")
		if lastColon > lastSlash {
			repository = remainder[:lastColon]
			reference = remainder[lastColon+1:]
		} else {
			repository = remainder
			reference = "latest"
		}
	}

	if registry == "registry-1.docker.io" && !strings.Contains(repository, "/") {
		repository = "library/" + repository
	}
	if repository == "" || reference == "" {
		return "", "", "", fmt.Errorf("invalid image reference %q", image)
	}
	return registry, repository, reference, nil
}

func loadCertificates(filename string) ([]DistrustedCertificate, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var document struct {
		Certificates []DistrustedCertificate `json:"certificates"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("decode certificate database: %w", err)
	}
	if len(document.Certificates) == 0 {
		return nil, fmt.Errorf("no certificates found in %s", filename)
	}

	for index := range document.Certificates {
		cert := &document.Certificates[index]
		block, _ := pem.Decode([]byte(cert.PEM))
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("invalid PEM certificate for %q", cert.Name)
		}
		actual := sha256.Sum256(block.Bytes)
		actualHex := hex.EncodeToString(actual[:])
		expected := strings.ToLower(cert.SHA256)
		if actualHex != expected {
			return nil, fmt.Errorf(
				"certificate fingerprint mismatch for %s: expected %s, got %s",
				cert.Name,
				expected,
				actualHex,
			)
		}
		cert.SHA256 = expected
		cert.DER = block.Bytes
	}
	return document.Certificates, nil
}

func verifyDigest(data []byte, digest string) error {
	algorithm, expected, found := strings.Cut(digest, ":")
	if !found {
		return fmt.Errorf("invalid digest %q", digest)
	}
	if algorithm != "sha256" {
		return fmt.Errorf("unsupported digest algorithm: %s", algorithm)
	}
	actual := sha256.Sum256(data)
	actualHex := hex.EncodeToString(actual[:])
	if actualHex != expected {
		return fmt.Errorf("digest mismatch: expected %s, got sha256:%s", digest, actualHex)
	}
	return nil
}

func selectManifest(manifest imageManifest) (manifestDescriptor, bool) {
	if len(manifest.Manifests) == 0 {
		return manifestDescriptor{}, false
	}
	for _, wanted := range []struct{ os, arch string }{
		{os: "linux", arch: "amd64"},
		{os: "linux", arch: "arm64"},
	} {
		for _, candidate := range manifest.Manifests {
			if candidate.Platform.OS == wanted.os &&
				candidate.Platform.Architecture == wanted.arch {
				return candidate, true
			}
		}
	}
	return manifest.Manifests[0], true
}

func isJavaRuntimePath(filename string) bool {
	normalized := strings.ToLower(strings.Trim(filename, "/"))
	base := path.Base(normalized)
	if base == "libjvm.so" || base == "jvm.dll" {
		return true
	}
	return (base == "java" || base == "java.exe" || base == "javaw.exe") &&
		strings.Contains("/"+normalized, "/bin/")
}

func isDefaultJavaTrustStore(filename string) bool {
	normalized := strings.ToLower(strings.Trim(filename, "/"))
	base := path.Base(normalized)
	if !defaultTrustStoreNames[base] {
		return false
	}
	if normalized == "etc/ssl/certs/java/cacerts" {
		return true
	}
	for _, part := range strings.Split(normalized, "/") {
		if part == "security" {
			return true
		}
	}
	return false
}

func imageJavaSettings(config imageConfig) (map[string]bool, []string, bool) {
	configured := make(map[string]bool)
	evidence := make([]string, 0)
	jvmStartup := false
	workingDir := config.Config.WorkingDir
	if workingDir == "" {
		workingDir = "/"
	}

	configValues := append([]string{}, config.Config.Env...)
	configValues = append(configValues, config.Config.Entrypoint...)
	configValues = append(configValues, config.Config.Cmd...)
	for _, value := range configValues {
		for _, match := range trustStorePropertyRE.FindAllStringSubmatch(value, -1) {
			storePath := match[1]
			if strings.Contains(storePath, "$") {
				evidence = append(evidence, "Unresolved Java trust-store setting: "+storePath)
				jvmStartup = true
				continue
			}
			if !strings.HasPrefix(storePath, "/") {
				storePath = path.Join(workingDir, storePath)
			}
			storePath = strings.TrimPrefix(path.Clean(storePath), "/")
			configured[storePath] = true
			evidence = append(evidence, "Configured Java trust store: "+storePath)
			jvmStartup = true
		}
	}

	for _, item := range append(append([]string{}, config.Config.Entrypoint...), config.Config.Cmd...) {
		if javaStartupRE.MatchString(item) {
			jvmStartup = true
			evidence = append(evidence, "Image startup command: "+item)
		}
	}
	return configured, evidence, jvmStartup
}

func findCertificates(data []byte, certificates []DistrustedCertificate) []CertificateMatch {
	found := make(map[string]CertificateMatch)
	for _, cert := range certificates {
		if bytes.Contains(data, cert.DER) {
			found[cert.SHA256] = CertificateMatch{
				Name: cert.Name, Kind: cert.Kind, SHA256: cert.SHA256,
			}
		}
	}

	for _, pemMatch := range pemCertificateRE.FindAll(data, -1) {
		normalized := normalizePEM(pemMatch)
		for _, cert := range certificates {
			if normalized == normalizePEM([]byte(cert.PEM)) {
				found[cert.SHA256] = CertificateMatch{
					Name: cert.Name, Kind: cert.Kind, SHA256: cert.SHA256,
				}
			}
		}
	}

	matches := make([]CertificateMatch, 0, len(found))
	for _, cert := range certificates {
		if match, ok := found[cert.SHA256]; ok {
			matches = append(matches, match)
		}
	}
	return matches
}

func normalizePEM(data []byte) string {
	lines := strings.Split(string(data), "\n")
	for index := range lines {
		lines[index] = strings.TrimSpace(lines[index])
	}
	return strings.Join(lines, "\n")
}

func removeUnderPrefix(records map[string]Finding, prefix string) {
	for filename := range records {
		if strings.HasPrefix(filename, prefix) {
			delete(records, filename)
		}
	}
}

func removeStoresUnderPrefix(records map[string]JavaTrustStore, prefix string) {
	for filename := range records {
		if strings.HasPrefix(filename, prefix) {
			delete(records, filename)
		}
	}
}

func removeRuntimeUnderPrefix(records map[string]string, prefix string) {
	for filename := range records {
		if strings.HasPrefix(filename, prefix) {
			delete(records, filename)
		}
	}
}

func removeDeletedPath[T any](records map[string]T, deletedPath string) {
	for filename := range records {
		if filename == deletedPath || strings.HasPrefix(filename, deletedPath+"/") {
			delete(records, filename)
		}
	}
}

func scanLayer(
	stream io.Reader,
	layerDigest string,
	certificates []DistrustedCertificate,
	filesystemFindings map[string]Finding,
	javaTrustStores map[string]JavaTrustStore,
	javaRuntimeFiles map[string]string,
	configuredTrustStores map[string]bool,
) error {
	hasher := sha256.New()
	buffered := bufio.NewReader(io.TeeReader(stream, hasher))
	var tarStream io.Reader = buffered
	var gzipReader *gzip.Reader

	magic, peekErr := buffered.Peek(2)
	if peekErr == nil && len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		var err error
		gzipReader, err = gzip.NewReader(buffered)
		if err != nil {
			return fmt.Errorf("open gzip layer: %w", err)
		}
		tarStream = gzipReader
	}

	tarReader := tar.NewReader(tarStream)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read image layer tar: %w", err)
		}

		filename := strings.TrimLeft(header.Name, "./")
		if filename == "" {
			continue
		}
		parent := path.Dir(filename)
		if parent == "." {
			parent = ""
		}
		base := path.Base(filename)

		if base == ".wh..wh..opq" {
			prefix := parent
			if prefix != "" {
				prefix += "/"
			}
			removeUnderPrefix(filesystemFindings, prefix)
			removeStoresUnderPrefix(javaTrustStores, prefix)
			removeRuntimeUnderPrefix(javaRuntimeFiles, prefix)
			continue
		}
		if strings.HasPrefix(base, ".wh.") {
			deleted := strings.TrimPrefix(base, ".wh.")
			deletedPath := path.Join(parent, deleted)
			removeDeletedPath(filesystemFindings, deletedPath)
			removeDeletedPath(javaTrustStores, deletedPath)
			removeDeletedPath(javaRuntimeFiles, deletedPath)
			continue
		}

		if isJavaRuntimePath(filename) {
			javaRuntimeFiles[filename] = layerDigest
		}
		isTrustStore := configuredTrustStores[filename] || isDefaultJavaTrustStore(filename)

		// Replacing a path in a later layer invalidates its earlier evidence.
		delete(filesystemFindings, filename)
		delete(javaTrustStores, filename)

		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			continue
		}
		content, err := io.ReadAll(tarReader)
		if err != nil {
			return fmt.Errorf("read image file %s: %w", filename, err)
		}
		matches := findCertificates(content, certificates)
		fileHash := sha256.Sum256(content)
		fileSHA256 := hex.EncodeToString(fileHash[:])

		if len(matches) > 0 {
			filesystemFindings[filename] = Finding{
				Path: filename, LayerDigest: layerDigest,
				FileSHA256: fileSHA256, Certificates: matches,
			}
		}
		if isTrustStore {
			javaTrustStores[filename] = JavaTrustStore{
				Path: filename, LayerDigest: layerDigest,
				FileSHA256: fileSHA256, Certificates: matches,
			}
		}
	}

	if gzipReader != nil {
		if _, err := io.Copy(io.Discard, gzipReader); err != nil {
			gzipReader.Close()
			return fmt.Errorf("finish gzip layer: %w", err)
		}
		if err := gzipReader.Close(); err != nil {
			return fmt.Errorf("close gzip layer: %w", err)
		}
	} else if _, err := io.Copy(io.Discard, buffered); err != nil {
		return fmt.Errorf("finish image layer: %w", err)
	}

	algorithm, expected, found := strings.Cut(layerDigest, ":")
	if !found || algorithm != "sha256" {
		return fmt.Errorf("unsupported image layer digest: %s", layerDigest)
	}
	actual := hex.EncodeToString(hasher.Sum(nil))
	if actual != expected {
		return fmt.Errorf("layer digest mismatch for %s: sha256:%s", layerDigest, actual)
	}
	return nil
}

func scanImage(target ImageTarget, certificates []DistrustedCertificate) ImageResult {
	result := ImageResult{
		Image: target.Image, Namespace: target.Namespace,
		Application: target.Application, Status: "UNKNOWN",
		Findings: []Finding{}, JVMEvidence: []string{},
		JavaTrustStores: []JavaTrustStore{},
	}

	registry, repository, reference, err := parseImageReference(target.Image)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	client := newRegistryClient(registry)

	manifestPath := fmt.Sprintf("/v2/%s/manifests/%s", repository, reference)
	var manifest imageManifest
	if err := client.getJSON(manifestPath, manifestAccept, &manifest); err != nil {
		result.Error = err.Error()
		return result
	}

	if selected, isIndex := selectManifest(manifest); isIndex {
		if selected.Digest == "" {
			result.Error = "manifest index entry has no digest"
			return result
		}
		manifest = imageManifest{}
		if err := client.getJSON(
			fmt.Sprintf("/v2/%s/manifests/%s", repository, selected.Digest),
			manifestAccept,
			&manifest,
		); err != nil {
			result.Error = err.Error()
			return result
		}
	}

	configDigest := manifest.Config.Digest
	if configDigest == "" {
		result.Error = "image manifest has no config digest"
		return result
	}
	configBytes, err := client.getBlob(repository, configDigest)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if err := verifyDigest(configBytes, configDigest); err != nil {
		result.Error = err.Error()
		return result
	}
	var config imageConfig
	if err := json.Unmarshal(configBytes, &config); err != nil {
		result.Error = fmt.Sprintf("invalid image config JSON: %v", err)
		return result
	}
	configuredStores, evidence, jvmStartup := imageJavaSettings(config)
	result.JVMEvidence = evidence

	if manifest.Layers == nil {
		result.Error = "image manifest contains no layers"
		return result
	}

	filesystemFindings := make(map[string]Finding)
	javaTrustStores := make(map[string]JavaTrustStore)
	javaRuntimeFiles := make(map[string]string)
	for _, layer := range manifest.Layers {
		if layer.Digest == "" {
			result.Error = "image layer has no digest"
			return result
		}
		layerStream, err := client.openBlob(repository, layer.Digest)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		err = scanLayer(
			layerStream,
			layer.Digest,
			certificates,
			filesystemFindings,
			javaTrustStores,
			javaRuntimeFiles,
			configuredStores,
		)
		closeErr := layerStream.Close()
		if err != nil {
			result.Error = err.Error()
			return result
		}
		if closeErr != nil {
			result.Error = fmt.Sprintf("close image layer %s: %v", layer.Digest, closeErr)
			return result
		}
	}

	result.JVMDetected = jvmStartup || len(javaRuntimeFiles) > 0
	for filename, digest := range javaRuntimeFiles {
		result.JVMEvidence = append(
			result.JVMEvidence,
			fmt.Sprintf("JVM runtime file: %s (layer %s)", filename, digest),
		)
	}
	sort.Strings(result.JVMEvidence)

	for _, finding := range filesystemFindings {
		result.Findings = append(result.Findings, finding)
	}
	sort.Slice(result.Findings, func(i, j int) bool {
		return result.Findings[i].Path < result.Findings[j].Path
	})
	for _, store := range javaTrustStores {
		result.JavaTrustStores = append(result.JavaTrustStores, store)
	}
	sort.Slice(result.JavaTrustStores, func(i, j int) bool {
		return result.JavaTrustStores[i].Path < result.JavaTrustStores[j].Path
	})

	result.Status = "PATCHED"
	if len(result.Findings) > 0 {
		result.Status = "VULNERABLE"
	}
	return result
}

func scanTargets(
	targets []ImageTarget,
	parallelism int,
	scan func(ImageTarget) ImageResult,
) []ImageResult {
	results := make([]ImageResult, len(targets))
	if len(targets) == 0 {
		return results
	}
	if parallelism > len(targets) {
		parallelism = len(targets)
	}

	type cacheEntry struct {
		done   chan struct{}
		result ImageResult
	}
	cache := make(map[string]*cacheEntry)
	var cacheMu sync.Mutex

	// Keep successful results for this run and retry UNKNOWN results.
	scanCached := func(target ImageTarget) ImageResult {
		for {
			cacheMu.Lock()
			entry, exists := cache[target.Image]
			if exists {
				cacheMu.Unlock()
				<-entry.done
				if entry.result.Status != "UNKNOWN" {
					return resultForTarget(entry.result, target)
				}
				continue
			}

			entry = &cacheEntry{done: make(chan struct{})}
			cache[target.Image] = entry
			cacheMu.Unlock()

			result := scan(target)

			cacheMu.Lock()
			entry.result = result
			if result.Status == "UNKNOWN" {
				delete(cache, target.Image)
			}
			close(entry.done)
			cacheMu.Unlock()
			return resultForTarget(result, target)
		}
	}

	jobs := make(chan int)
	var workers sync.WaitGroup
	workers.Add(parallelism)
	for worker := 0; worker < parallelism; worker++ {
		go func() {
			defer workers.Done()
			for index := range jobs {
				results[index] = scanCached(targets[index])
			}
		}()
	}

	for index := range targets {
		jobs <- index
	}
	close(jobs)
	workers.Wait()
	return results
}

func resultForTarget(result ImageResult, target ImageTarget) ImageResult {
	result.Image = target.Image
	result.Namespace = target.Namespace
	result.Application = target.Application
	return result
}

func parseParallelism(value string) (int, error) {
	parallelism, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("must be an integer")
	}
	if parallelism < 1 || parallelism > maxParallelImages {
		return 0, fmt.Errorf("must be between 1 and %d", maxParallelImages)
	}
	return parallelism, nil
}

func isCSVHeader(row []string) bool {
	if len(row) < 3 {
		return false
	}
	header := make([]string, 3)
	for index, column := range row[:3] {
		header[index] = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(column, "\ufeff")))
	}
	return (header[0] == "namespace" || header[0] == "kubernetes namespace") &&
		(header[1] == "application" || header[1] == "application name" || header[1] == "app") &&
		(header[2] == "image" || header[2] == "image name" || header[2] == "image reference")
}

func readTargets(positionalImages []string, imageFile string) ([]ImageTarget, error) {
	targets := make([]ImageTarget, 0, len(positionalImages))
	for _, image := range positionalImages {
		image = strings.TrimSpace(image)
		if image != "" {
			targets = append(targets, ImageTarget{Image: image})
		}
	}

	if imageFile != "" {
		var source io.Reader
		var file *os.File
		if imageFile == "-" {
			source = os.Stdin
		} else {
			var err error
			file, err = os.Open(imageFile)
			if err != nil {
				return nil, err
			}
			defer file.Close()
			source = file
		}

		reader := csv.NewReader(source)
		reader.FieldsPerRecord = -1
		firstRecord := true
		for {
			row, err := reader.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				line := ""
				if parseErr, ok := err.(*csv.ParseError); ok {
					line = fmt.Sprintf(":%d", parseErr.Line)
				}
				return nil, fmt.Errorf("%s%s: invalid CSV: %w", imageFile, line, err)
			}
			if len(row) == 0 || allBlank(row) {
				continue
			}
			if strings.HasPrefix(strings.TrimSpace(row[0]), "#") {
				continue
			}
			if firstRecord && isCSVHeader(row) {
				firstRecord = false
				continue
			}
			firstRecord = false
			line, _ := reader.FieldPos(0)
			if len(row) < 3 {
				return nil, fmt.Errorf(
					"%s:%d: expected at least 3 CSV columns (namespace, application, image)",
					imageFile,
					line,
				)
			}
			target := ImageTarget{
				Namespace:   strings.TrimSpace(row[0]),
				Application: strings.TrimSpace(row[1]),
				Image:       strings.TrimSpace(row[2]),
			}
			if target.Namespace == "" || target.Application == "" || target.Image == "" {
				return nil, fmt.Errorf(
					"%s:%d: namespace, application, and image must not be empty",
					imageFile,
					line,
				)
			}
			targets = append(targets, target)
		}
	}

	seen := make(map[ImageTarget]bool)
	unique := make([]ImageTarget, 0, len(targets))
	for _, target := range targets {
		if !seen[target] {
			seen[target] = true
			unique = append(unique, target)
		}
	}
	return unique, nil
}

func allBlank(row []string) bool {
	for _, value := range row {
		if strings.TrimSpace(value) != "" {
			return false
		}
	}
	return true
}

func printResultsTable(results []ImageResult) {
	headers := []string{
		"namespace",
		"application name",
		"image name",
		"vulnerability status",
	}
	rows := make([][]string, 0, len(results))
	for _, result := range results {
		namespace := result.Namespace
		if namespace == "" {
			namespace = "-"
		}
		application := result.Application
		if application == "" {
			application = "-"
		}
		rows = append(rows, []string{
			namespace, application, result.Image, result.Status,
		})
	}
	widths := make([]int, len(headers))
	for index, header := range headers {
		widths[index] = len(header)
	}
	for _, row := range rows {
		for index, value := range row {
			if len(value) > widths[index] {
				widths[index] = len(value)
			}
		}
	}
	printTableRow(headers, widths)
	separators := make([]string, len(widths))
	for index, width := range widths {
		separators[index] = strings.Repeat("-", width)
	}
	fmt.Println(strings.Join(separators, "-+-"))
	for _, row := range rows {
		printTableRow(row, widths)
	}
}

func printTableRow(row []string, widths []int) {
	cells := make([]string, len(row))
	for index, value := range row {
		cells[index] = value + strings.Repeat(" ", widths[index]-len(value))
	}
	fmt.Println(strings.Join(cells, " | "))
}

func defaultCertificatePath() string {
	if executable, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(executable), "distrusted-certs.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	if _, source, _, ok := runtime.Caller(0); ok {
		candidate := filepath.Join(filepath.Dir(source), "distrusted-certs.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return "distrusted-certs.json"
}

func run() int {
	defaultParallelism := maxParallelImages
	var parallelismEnvError error
	if value := strings.TrimSpace(os.Getenv(parallelismEnvVar)); value != "" {
		parsed, err := parseParallelism(value)
		if err != nil {
			parallelismEnvError = fmt.Errorf("%s %s: %w", parallelismEnvVar, value, err)
		} else {
			defaultParallelism = parsed
		}
	}

	imageFile := flag.String("f", "", "CSV with namespace, application, and image in the first three columns; use '-' for stdin")
	flag.StringVar(imageFile, "image-file", "", "CSV with namespace, application, and image in the first three columns; use '-' for stdin")
	certificateFile := flag.String("c", defaultCertificatePath(), "certificate database JSON file")
	flag.StringVar(certificateFile, "certificates", defaultCertificatePath(), "certificate database JSON file")
	jsonOutput := flag.Bool("json", false, "emit one JSON object per image")
	parallelism := flag.Int(
		"parallel",
		defaultParallelism,
		fmt.Sprintf(
			"number of images to scan concurrently (1-%d; default from %s or %d)",
			maxParallelImages,
			parallelismEnvVar,
			maxParallelImages,
		),
	)
	flag.Parse()

	parallelismExplicit := false
	flag.Visit(func(parsedFlag *flag.Flag) {
		if parsedFlag.Name == "parallel" {
			parallelismExplicit = true
		}
	})
	if parallelismEnvError != nil && !parallelismExplicit {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", parallelismEnvError)
		return 3
	}
	if *parallelism < 1 || *parallelism > maxParallelImages {
		fmt.Fprintf(
			os.Stderr,
			"configuration error: --parallel must be between 1 and %d\n",
			maxParallelImages,
		)
		return 3
	}

	targets, err := readTargets(flag.Args(), *imageFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "input error: %v\n", err)
		return 3
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "usage error: provide image references or a non-empty --image-file")
		return 2
	}

	certificates, err := loadCertificates(*certificateFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "certificate database error: %v\n", err)
		return 3
	}

	var progress sync.Mutex
	results := scanTargets(targets, *parallelism, func(target ImageTarget) ImageResult {
		label := target.Image
		if target.Namespace != "" || target.Application != "" {
			label = fmt.Sprintf("%s/%s (%s)", target.Namespace, target.Application, target.Image)
		}
		progress.Lock()
		fmt.Fprintf(os.Stderr, "Scanning %s...\n", label)
		progress.Unlock()
		return scanImage(target, certificates)
	})

	exitCode := 0
	for _, result := range results {
		if result.Status == "VULNERABLE" && exitCode < 1 {
			exitCode = 1
		} else if result.Status == "UNKNOWN" && exitCode < 2 {
			exitCode = 2
		}
	}

	if *jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		for _, result := range results {
			if err := encoder.Encode(result); err != nil {
				fmt.Fprintf(os.Stderr, "output error: %v\n", err)
				return 3
			}
		}
	} else {
		printResultsTable(results)
	}
	return exitCode
}

func main() {
	os.Exit(run())
}
