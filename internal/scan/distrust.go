package scan

import (
	"slices"
	"strings"
)

// Trust states of a finding. Only trusted findings make an image VULNERABLE.
const (
	TrustTrusted = "trusted"
	// TrustDistrusted is a certificate in a p11-kit blocklist directory.
	TrustDistrusted = "distrusted"
	// TrustDisabled is a certificate that /etc/ca-certificates.conf deselects.
	TrustDisabled = "disabled"
)

// caCertificatesConf selects the certificates in /usr/share/ca-certificates
// on Debian and Ubuntu.
const caCertificatesConf = "etc/ca-certificates.conf"

// detectCAConf keeps the content of /etc/ca-certificates.conf, which decides
// the trust state of the certificates in /usr/share/ca-certificates.
func detectCAConf(entry fileEntry) []evidence {
	if !entry.regular || entry.path != caCertificatesConf {
		return nil
	}
	return []evidence{{caConf: entry.data}}
}

// isBlocklistPath reports whether a file is in a p11-kit blocklist directory,
// such as /etc/pki/ca-trust/source/blocklist on Red Hat and Fedora. p11-kit
// distrusts every certificate in it. The older directory name is blacklist.
func isBlocklistPath(file string) bool {
	parts := strings.Split(file, "/")
	inList := slices.Contains(parts, "blocklist") || slices.Contains(parts, "blacklist")
	return inList && (strings.Contains(file, "pki/") || strings.Contains(file, "trust-source/"))
}

// deselectedCertificates returns the certificate files that a
// /etc/ca-certificates.conf deselects with a leading "!".
func deselectedCertificates(conf []byte) map[string]bool {
	deselected := make(map[string]bool)
	for line := range strings.Lines(string(conf)) {
		if name, found := strings.CutPrefix(strings.TrimSpace(line), "!"); found && name != "" {
			deselected["usr/share/ca-certificates/"+name] = true
		}
	}
	return deselected
}

// classifyTrust sets the trust state of each finding and reports whether any
// finding is still trusted.
func classifyTrust(findings []Finding, conf []byte) bool {
	deselected := deselectedCertificates(conf)
	anyTrusted := false
	for index := range findings {
		switch file := findings[index].Path; {
		case isBlocklistPath(file):
			findings[index].Trust = TrustDistrusted
		case deselected[file]:
			findings[index].Trust = TrustDisabled
		default:
			findings[index].Trust = TrustTrusted
			anyTrusted = true
		}
	}
	return anyTrusted
}
