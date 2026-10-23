package scan

import (
	"bytes"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestIsBlocklistPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path string
		want bool
	}{
		{"etc/pki/ca-trust/source/blocklist/emsign.pem", true},
		{"usr/share/pki/ca-trust-source/blacklist/emsign.crt", true},
		{"etc/ca-certificates/trust-source/blocklist/emsign.p11-kit", true},
		{"etc/pki/ca-trust/source/anchors/emsign.pem", false},
		{"app/blocklist/emsign.pem", false},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			t.Parallel()
			if got := isBlocklistPath(test.path); got != test.want {
				t.Errorf("isBlocklistPath(%q) = %t, want %t", test.path, got, test.want)
			}
		})
	}
}

func TestClassifyTrust(t *testing.T) {
	t.Parallel()
	conf := []byte("# comment\nmozilla/AAA_Certificate_Services.crt\n!mozilla/emSign_ECC_Root_CA_-_G3.crt\n")
	findings := []Finding{
		{Path: "usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt"},
		{Path: "etc/pki/ca-trust/source/blocklist/emsign.pem"},
	}
	if classifyTrust(findings, conf) {
		t.Error("classifyTrust found a trusted certificate, want none")
	}
	if findings[0].Trust != TrustDisabled || findings[1].Trust != TrustDistrusted {
		t.Errorf("trust = %q, %q; want disabled, distrusted", findings[0].Trust, findings[1].Trust)
	}

	findings = append(findings, Finding{Path: "usr/share/ca-certificates/mozilla/AAA_Certificate_Services.crt"})
	if !classifyTrust(findings, conf) || findings[2].Trust != TrustTrusted {
		t.Errorf("selected certificate trust = %q, want trusted", findings[2].Trust)
	}
}

// TestImageScan_CACertificatesConf follows /etc/ca-certificates.conf through
// layers that change and delete it.
func TestImageScan_CACertificatesConf(t *testing.T) {
	t.Parallel()
	scan := newImageScan(v1.Config{}, nil)
	applyLayer := func(files map[string][]byte) {
		t.Helper()
		layer := makeTestTar(t, files)
		if err := scan.scanLayer(bytes.NewReader(layer), layerDigest(layer)); err != nil {
			t.Fatal(err)
		}
	}

	applyLayer(map[string][]byte{caCertificatesConf: []byte("mozilla/a.crt\n")})
	applyLayer(map[string][]byte{caCertificatesConf: []byte("!mozilla/a.crt\n")})
	if string(scan.collect().caConf) != "!mozilla/a.crt\n" {
		t.Fatalf("caConf = %q, want the replacement", scan.collect().caConf)
	}
	applyLayer(map[string][]byte{"etc/.wh.ca-certificates.conf": nil})
	if scan.collect().caConf != nil {
		t.Fatalf("caConf = %q, want nil after a whiteout", scan.collect().caConf)
	}
}
