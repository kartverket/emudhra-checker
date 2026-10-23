// Package certdb holds the distrusted certificate database and finds its
// certificates in file contents.
package certdb

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"regexp"
	"strings"
)

const certificateDatabase = "distrusted-certs.json"

//go:embed distrusted-certs.json
var embeddedFiles embed.FS

var (
	pemCertificateRE = regexp.MustCompile(`(?s)-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----`)
	// literalJoinRE matches where a PEM body continues in the next string
	// literal: "..." + "..." in JavaScript, adjacent "..." "..." in C.
	literalJoinRE = regexp.MustCompile("[\"'`]\\s*\\+?\\s*[\"'`]")
)

// DistrustedCertificate is one entry of the certificate database: a root or
// intermediate CA certificate that images must not trust.
type DistrustedCertificate struct {
	SHA256 string `json:"sha256"`
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	PEM    string `json:"pem"`
	DER    []byte `json:"-"`
	// JVMFingerprints lists what a JDK blocked.certs file needs to block an
	// intermediate. It is empty for roots, which are distrusted, not blocked.
	JVMFingerprints []string `json:"-"`
}

// CertificateMatch names a database certificate that Find found in a file.
type CertificateMatch struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
}

// Load reads the certificate database from filename, or the copy
// embedded in the binary when filename is empty.
func Load(filename string) ([]DistrustedCertificate, error) {
	source := filename
	var data []byte
	var err error
	if filename == "" {
		source = "embedded " + certificateDatabase
		data, err = embeddedFiles.ReadFile(certificateDatabase)
	} else {
		data, err = os.ReadFile(filename)
	}
	if err != nil {
		return nil, err
	}

	var document struct {
		Certificates []DistrustedCertificate `json:"certificates"`
	}
	err = json.Unmarshal(data, &document)
	if err != nil {
		return nil, fmt.Errorf("decode certificate database %s: %w", source, err)
	}
	if len(document.Certificates) == 0 {
		return nil, fmt.Errorf("no certificates found in %s", source)
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
		if cert.Kind == "intermediate" {
			cert.JVMFingerprints, err = jvmFingerprints(cert.DER)
			if err != nil {
				return nil, fmt.Errorf("blocked.certs fingerprints for %s: %w", cert.Name, err)
			}
		}
	}
	return document.Certificates, nil
}

// Find returns the certificates that occur in data, in database order. It
// finds them as DER bytes, which covers JKS and PKCS#12 stores and binaries,
// and as PEM in any line layout.
func Find(data []byte, certificates []DistrustedCertificate) []CertificateMatch {
	found := make(map[string]CertificateMatch)
	for _, cert := range certificates {
		if bytes.Contains(data, cert.DER) {
			found[cert.SHA256] = CertificateMatch{
				Name: cert.Name, Kind: cert.Kind, SHA256: cert.SHA256,
			}
		}
	}

	for _, pemMatch := range pemCertificateRE.FindAllSubmatch(data, -1) {
		der := decodePEMBody(pemMatch[1])
		for _, cert := range certificates {
			if bytes.Equal(der, cert.DER) {
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

// decodePEMBody decodes the base64 body of a PEM certificate whatever its line
// width, line endings or indentation (Node.js compiles its roots in with
// 72-character lines), and also when it is written as escaped string literals
// in source code, such as JavaScript in node_modules. It returns nil when the
// body is not valid base64.
func decodePEMBody(body []byte) []byte {
	body = literalJoinRE.ReplaceAll(body, nil)
	for _, escape := range []string{`\r`, `\n`, `\t`} {
		body = bytes.ReplaceAll(body, []byte(escape), nil)
	}
	encoded := make([]byte, 0, len(body))
	for _, c := range body {
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '+' || c == '/' || c == '=' {
			encoded = append(encoded, c)
		}
	}
	der, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		return nil
	}
	return der
}
