package scan

import (
	"github.com/kartverket/emudhra-checker/internal/certdb"
	"github.com/kartverket/emudhra-checker/internal/inventory"
)

const (
	// StatusPatched means that the image has no trusted copy of a listed certificate.
	StatusPatched = "PATCHED"
	// StatusVulnerable means that the image trusts at least one listed certificate.
	StatusVulnerable = "VULNERABLE"
	// StatusMitigated means that the image trusts a listed certificate, but
	// every JDK in it blocks all encodings of the compromised intermediates.
	// Java refuses the leaked keys. Programs that use the system CA bundle do not.
	StatusMitigated = "MITIGATED"
	// StatusPartiallyMitigated means that the JDKs block only some encodings of
	// the compromised intermediates. A re-encoded certificate gets past the list.
	StatusPartiallyMitigated = "PARTIALLY_MITIGATED"
	// StatusUnknown means that the scanner downloaded the image but cannot read it.
	StatusUnknown = "UNKNOWN"
	// StatusPullError means the registry did not hand out the image: it does
	// not exist, the credentials are missing or refused, or the registry failed.
	StatusPullError = "ERR_DOCKER_PULL"
)

// Finding is a file in the final image filesystem that contains listed
// certificates.
type Finding struct {
	Path         string                    `json:"path"`
	LayerDigest  string                    `json:"layer_digest"`
	FileSHA256   string                    `json:"file_sha256"`
	Certificates []certdb.CertificateMatch `json:"certificates"`
	Trust        string                    `json:"trust"` // trusted, distrusted or disabled
}

// JavaTrustStore is a Java trust store in the image: a default cacerts or
// jssecacerts, or a store that the image configures with
// -Djavax.net.ssl.trustStore. Certificates lists the listed certificates in it.
type JavaTrustStore struct {
	Path         string                    `json:"path"`
	LayerDigest  string                    `json:"layer_digest"`
	FileSHA256   string                    `json:"file_sha256"`
	Certificates []certdb.CertificateMatch `json:"certificates"`
}

// ImageResult is the scan result for one input row. Rows that name the same
// image share the scan and differ only in their target fields.
type ImageResult struct {
	Image           string           `json:"image"`
	Status          string           `json:"status"`
	Findings        []Finding        `json:"findings"`
	Cluster         string           `json:"cluster"`
	Namespace       string           `json:"namespace"`
	Kind            string           `json:"kind"`
	Application     string           `json:"application"`
	JVMDetected     bool             `json:"jvm_detected"`
	JVMEvidence     []string         `json:"jvm_evidence"`
	JavaTrustStores []JavaTrustStore `json:"java_truststores"`
	// Components are the runtimes, libraries and JDK blocked.certs files found.
	Components []Component `json:"components"`
	// Mitigation names a fix detected in the image, such as blocked.certs.
	// It does not change Status: other programs still trust the roots.
	Mitigation string `json:"mitigation"`
	Error      string `json:"error,omitempty"`
}

// Failed reports whether the scan of the image did not complete.
func (r ImageResult) Failed() bool {
	return r.Status == StatusUnknown || r.Status == StatusPullError
}

// newResult is an UNKNOWN result for target, with empty rather than nil lists.
func newResult(target inventory.ImageTarget) ImageResult {
	return resultForTarget(ImageResult{
		Status:   StatusUnknown,
		Findings: []Finding{}, JVMEvidence: []string{},
		JavaTrustStores: []JavaTrustStore{}, Components: []Component{},
	}, target)
}

func resultForTarget(result ImageResult, target inventory.ImageTarget) ImageResult {
	result.Image = target.Image
	result.Cluster = target.Cluster
	result.Namespace = target.Namespace
	result.Kind = target.Kind
	result.Application = target.Application
	return result
}
