package scan

import (
	"fmt"
	"path"
	"strings"

	"github.com/kartverket/emudhra-checker/internal/certdb"
)

// A JDK refuses every certificate whose SHA-256 fingerprint is listed in its
// lib/security/blocked.certs. When the file lists every encoding of every
// compromised intermediate (certdb's JVM fingerprints), Java clients reject
// the leaked keys even though cacerts still trusts the eMudhra and AAA roots.
const (
	BlockedComplete = "complete"
	BlockedPartial  = "partial"
	BlockedNone     = "none"
)

func detectBlockedCerts(needed map[string]bool) componentCheck {
	return func(file string, data []byte) (Component, bool) {
		if !isBlockedCertsPath(file) {
			return Component{}, false
		}
		return checkBlockedCerts(file, data, needed), true
	}
}

// isBlockedCertsPath matches lib/security/blocked.certs, and the
// blacklisted.certs that JDK 8 still uses for the same list.
func isBlockedCertsPath(filename string) bool {
	base := path.Base(filename)
	return (base == "blocked.certs" || base == "blacklisted.certs") &&
		strings.HasSuffix(path.Dir(filename), "lib/security")
}

// checkBlockedCerts counts how many of the needed fingerprints the file lists.
// The file has an Algorithm=SHA-256 line, # comments and one hex fingerprint
// per line.
func checkBlockedCerts(filename string, data []byte, needed map[string]bool) Component {
	listed := make(map[string]bool)
	for line := range strings.Lines(string(data)) {
		fingerprint := strings.ToUpper(strings.TrimSpace(line))
		if needed[fingerprint] {
			listed[fingerprint] = true
		}
	}
	result := Component{Kind: KindBlockedCerts, Path: filename, Blocked: len(listed), Needed: len(needed)}
	switch {
	case result.Blocked == 0:
		result.Status = BlockedNone
	case result.Blocked < result.Needed:
		result.Status = BlockedPartial
	default:
		result.Status = BlockedComplete
	}
	return result
}

// MitigationBlockedCerts names the blocked.certs method in scan results.
const MitigationBlockedCerts = "blocked.certs"

// weakestBlockedCerts returns the blocked.certs file that lists the fewest
// fingerprints. It is the zero Component when the image has no JDK.
func weakestBlockedCerts(components []Component) Component {
	var weakest Component
	for _, file := range components {
		if file.Kind == KindBlockedCerts && (weakest.Path == "" || file.Blocked < weakest.Blocked) {
			weakest = file
		}
	}
	return weakest
}

// mitigation names the fix the image's JDKs use: blocked.certs when every
// blocked.certs file lists all the fingerprints, with the weakest count when
// some are missing, and "" when a JDK blocks none (or there is no JDK).
func mitigation(components []Component) string {
	switch weakest := weakestBlockedCerts(components); weakest.Status {
	case BlockedComplete:
		return MitigationBlockedCerts
	case BlockedPartial:
		return fmt.Sprintf("%s (partial: %d/%d)", MitigationBlockedCerts, weakest.Blocked, weakest.Needed)
	}
	return ""
}

// trustedStatus is the status of an image that trusts a listed certificate.
// The weakest JDK decides, as for mitigation.
func trustedStatus(components []Component) string {
	switch weakestBlockedCerts(components).Status {
	case BlockedComplete:
		return StatusMitigated
	case BlockedPartial:
		return StatusPartiallyMitigated
	}
	return StatusVulnerable
}

func jvmFingerprints(certificates []certdb.DistrustedCertificate) map[string]bool {
	fingerprints := make(map[string]bool)
	for _, cert := range certificates {
		for _, fingerprint := range cert.JVMFingerprints {
			fingerprints[fingerprint] = true
		}
	}
	return fingerprints
}
