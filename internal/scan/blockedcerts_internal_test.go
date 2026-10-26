package scan

import (
	"bytes"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/kartverket/emudhra-checker/internal/certdb"
)

func TestIsBlockedCertsPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path string
		want bool
	}{
		{"usr/lib/jvm/temurin-25/lib/security/blocked.certs", true},
		{"opt/java/openjdk/jre/lib/security/blocked.certs", true},
		{"opt/java/openjdk/lib/security/blacklisted.certs", true},
		{"etc/blocked.certs", false},
		{"usr/lib/jvm/temurin-25/lib/security/cacerts", false},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			t.Parallel()
			if got := isBlockedCertsPath(test.path); got != test.want {
				t.Errorf("isBlockedCertsPath(%q) = %t, want %t", test.path, got, test.want)
			}
		})
	}
}

// blockedCertsFiles returns a complete blocked.certs (lowercase, with
// comments) and one with only each intermediate's own fingerprint.
func blockedCertsFiles(t *testing.T, certificates []certdb.DistrustedCertificate) (string, string) {
	t.Helper()
	var complete, canonical strings.Builder
	complete.WriteString("Algorithm=SHA-256\n# eMudhra\n")
	canonical.WriteString("Algorithm=SHA-256\n")
	for _, cert := range certificates {
		if cert.Kind != "intermediate" {
			continue
		}
		canonical.WriteString(strings.ToUpper(cert.SHA256) + "\n")
		for _, fingerprint := range cert.JVMFingerprints {
			complete.WriteString(strings.ToLower(fingerprint) + "\n")
		}
	}
	return complete.String(), canonical.String()
}

func TestCheckBlockedCerts(t *testing.T) {
	t.Parallel()
	certificates, err := certdb.Load("")
	if err != nil {
		t.Fatal(err)
	}
	needed := jvmFingerprints(certificates)
	complete, canonical := blockedCertsFiles(t, certificates)
	tests := []struct {
		name    string
		file    string
		blocked int
		status  string
	}{
		{"all encodings", complete, 48, BlockedComplete},
		{"only the 16 canonical fingerprints", canonical, 16, BlockedPartial},
		{"stock jdk entries", "Algorithm=SHA-256\n" + strings.Repeat("0", 64) + "\n", 0, BlockedNone},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := checkBlockedCerts("lib/security/blocked.certs", []byte(test.file), needed)
			if got.Blocked != test.blocked || got.Needed != 48 || got.Status != test.status {
				t.Errorf("checkBlockedCerts = %+v, want %d of 48 (%s)", got, test.blocked, test.status)
			}
		})
	}
}

func TestImageScan_BlockedCerts(t *testing.T) {
	t.Parallel()
	certificates, err := certdb.Load("")
	if err != nil {
		t.Fatal(err)
	}
	complete, _ := blockedCertsFiles(t, certificates)
	scan := newImageScan(v1.Config{}, certificates)
	file := "usr/lib/jvm/temurin-25/lib/security/blocked.certs"
	applyLayer := func(files map[string][]byte) {
		t.Helper()
		layer := makeTestTar(t, files)
		if scanErr := scan.scanLayer(bytes.NewReader(layer), layerDigest(layer)); scanErr != nil {
			t.Fatal(scanErr)
		}
	}

	applyLayer(map[string][]byte{file: []byte("Algorithm=SHA-256\n")})
	if got := componentOf(scan, file, KindBlockedCerts).Status; got != BlockedNone {
		t.Fatalf("stock file status = %q, want none", got)
	}
	applyLayer(map[string][]byte{file: []byte(complete)})
	if got := componentOf(scan, file, KindBlockedCerts).Status; got != BlockedComplete {
		t.Fatalf("patched file status = %q, want complete", got)
	}
	applyLayer(map[string][]byte{"usr/lib/jvm/temurin-25/lib/security/.wh.blocked.certs": nil})
	if len(scan.collect().components) != 0 {
		t.Fatal("whiteout should remove the blocked.certs record")
	}
}

func TestMitigation(t *testing.T) {
	t.Parallel()
	file := func(path string, blocked int, status string) Component {
		return Component{Kind: KindBlockedCerts, Path: path, Blocked: blocked, Needed: 48, Status: status}
	}
	tests := []struct {
		name       string
		files      []Component
		mitigation string
		status     string
	}{
		{"no jdk", nil, "", StatusVulnerable},
		{"stock blocked.certs", []Component{file("a", 0, BlockedNone)}, "", StatusVulnerable},
		{"complete", []Component{file("a", 48, BlockedComplete)}, "blocked.certs", StatusMitigated},
		{
			"only canonical fingerprints",
			[]Component{file("a", 16, BlockedPartial)},
			"blocked.certs (partial: 16/48)",
			StatusPartiallyMitigated,
		},
		{
			"one of two jdks unpatched",
			[]Component{file("a", 48, BlockedComplete), file("b", 0, BlockedNone)},
			"",
			StatusVulnerable,
		},
		{
			"weakest jdk wins",
			[]Component{file("a", 48, BlockedComplete), file("b", 16, BlockedPartial)},
			"blocked.certs (partial: 16/48)",
			StatusPartiallyMitigated,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := mitigation(test.files); got != test.mitigation {
				t.Errorf("mitigation = %q, want %q", got, test.mitigation)
			}
			if got := trustedStatus(test.files); got != test.status {
				t.Errorf("trustedStatus = %q, want %q", got, test.status)
			}
		})
	}
}
