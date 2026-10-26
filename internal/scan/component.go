package scan

import (
	"github.com/kartverket/emudhra-checker/internal/certdb"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"maps"
	"slices"
	"strings"
)

// Component kinds.
const (
	KindGo           = "go"
	KindJDK          = "jdk"
	KindNode         = "node"
	KindCertifi      = "certifi"
	KindPip          = "pip"
	KindBlockedCerts = "blocked.certs"
)

// Statuses of runtimes and libraries. A fixed version rejects the compromised
// intermediates whatever the image's CA bundle contains.
const (
	VersionFixed    = "fixed"
	VersionOutdated = "outdated"
	VersionUnknown  = "unknown"
)

// Component is a runtime, library or mitigation in the image whose version or
// content decides whether it accepts certificates from the compromised CAs.
type Component struct {
	Kind    string `json:"kind"`
	Path    string `json:"path"`
	Version string `json:"version,omitempty"`
	Status  string `json:"status"`
	Fixed   string `json:"fixed,omitempty"`   // release to upgrade to, for outdated components
	Note    string `json:"note,omitempty"`    // how the image configures the component, if that matters
	Blocked int    `json:"blocked,omitempty"` // blocked.certs: fingerprints of compromised intermediates listed
	Needed  int    `json:"needed,omitempty"`  // blocked.certs: fingerprints a complete list has
}

// A detector recognizes something in an image. image is what it found in the
// image config. entry reports what it finds in one entry of the final
// filesystem.
type detector struct {
	image []evidence
	entry func(fileEntry) []evidence
}

// A componentCheck recognizes one kind of component in a regular file from
// its path and content. It returns false for other files.
type componentCheck func(file string, data []byte) (Component, bool)

// componentDetector makes a detector from a component check.
func componentDetector(check componentCheck) detector {
	return detector{entry: func(entry fileEntry) []evidence {
		if !entry.regular {
			return nil
		}
		component, found := check(entry.path, entry.data)
		if !found {
			return nil
		}
		return []evidence{{component: &component}}
	}}
}

// detectorsFor builds the detectors for one image. A detector that depends on
// the image config, such as the JVM and Node.js detectors, reads it here.
func detectorsFor(config v1.Config, certificates []certdb.DistrustedCertificate) []detector {
	return []detector{
		{entry: detectFinding},
		jvmDetector(config),
		{entry: detectCAConf},
		componentDetector(detectGoBinary),
		componentDetector(detectJDK),
		componentDetector(nodeDetector(config)),
		componentDetector(detectPythonPackage),
		componentDetector(detectBlockedCerts(jvmFingerprints(certificates))),
	}
}

// detectFinding reports a regular file that contains listed certificates.
func detectFinding(entry fileEntry) []evidence {
	if !entry.regular || len(entry.certificates) == 0 {
		return nil
	}
	return []evidence{{finding: &Finding{
		Path:         entry.path,
		LayerDigest:  entry.layerDigest,
		FileSHA256:   entry.fileSHA256,
		Certificates: entry.certificates,
	}}}
}

// Summary describes an image's runtimes and libraries in one table cell: the
// worst status of each kind, such as "go:outdated jdk:fixed". blocked.certs is
// left out because it is reported as the mitigation.
func Summary(components []Component) string {
	worst := make(map[string]string)
	for _, component := range components {
		if component.Kind != KindBlockedCerts && versionRank(component.Status) > versionRank(worst[component.Kind]) {
			worst[component.Kind] = component.Status
		}
	}
	parts := make([]string, 0, len(worst))
	for _, kind := range slices.Sorted(maps.Keys(worst)) {
		parts = append(parts, kind+":"+worst[kind])
	}
	return strings.Join(parts, " ")
}

// versionRank orders statuses from best to worst. Other values rank lowest.
func versionRank(status string) int {
	return slices.Index([]string{VersionFixed, VersionUnknown, VersionOutdated}, status)
}
