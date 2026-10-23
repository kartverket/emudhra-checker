package certdb_test

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kartverket/emudhra-checker/internal/certdb"
)

func TestLoadCertificates(t *testing.T) {
	t.Parallel()
	embedded, err := certdb.Load("")
	if err != nil {
		t.Fatal(err)
	}
	if len(embedded) == 0 {
		t.Fatal("expected certificates in the embedded database")
	}

	t.Run("fingerprint mismatch", func(t *testing.T) {
		t.Parallel()
		tampered := embedded[0]
		tampered.SHA256 = strings.Repeat("0", len(tampered.SHA256))
		data, marshalErr := json.Marshal(map[string]any{"certificates": []certdb.DistrustedCertificate{tampered}})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		filename := filepath.Join(t.TempDir(), "distrusted-certs.json")
		if writeErr := os.WriteFile(filename, data, 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}

		_, loadErr := certdb.Load(filename)
		if loadErr == nil || !strings.Contains(loadErr.Error(), "fingerprint mismatch") {
			t.Fatalf("certdb.Load error = %v, want a fingerprint mismatch", loadErr)
		}
	})
}

// TestJVMFingerprints checks the port of OpenJDK's BlockedCertsConverter
// against the fingerprints it publishes for the compromised intermediates.
func TestJVMFingerprints(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("testdata", "blocked-certs.txt"))
	if err != nil {
		t.Fatal(err)
	}
	want := make(map[string]bool)
	for line := range strings.Lines(string(data)) {
		if line = strings.TrimSpace(line); len(line) == 64 {
			want[line] = true
		}
	}

	certificates, err := certdb.Load("")
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]bool)
	for _, cert := range certificates {
		if cert.Kind == "intermediate" && !slices.Contains(cert.JVMFingerprints, strings.ToUpper(cert.SHA256)) {
			t.Errorf("%s: JVM fingerprints do not include its own SHA-256", cert.Name)
		}
		for _, fingerprint := range cert.JVMFingerprints {
			got[fingerprint] = true
		}
	}
	if len(want) != 48 || !maps.Equal(got, want) {
		t.Errorf("got %d JVM fingerprints, want the %d in testdata/blocked-certs.txt", len(got), len(want))
	}
}

// wrap splits encoded into lines of width characters.
func wrap(encoded string, width int) []string {
	var lines []string
	for len(encoded) > width {
		lines = append(lines, encoded[:width])
		encoded = encoded[width:]
	}
	return append(lines, encoded)
}

func TestFind(t *testing.T) {
	t.Parallel()
	certificates, err := certdb.Load("")
	if err != nil {
		t.Fatal(err)
	}
	root := certificates[0]
	encoded := base64.StdEncoding.EncodeToString(root.DER)
	pemWith := func(width int, newline, indent string) string {
		lines := wrap(encoded, width)
		return indent + "-----BEGIN CERTIFICATE-----" + newline + indent +
			strings.Join(lines, newline+indent) + newline + indent + "-----END CERTIFICATE-----" + newline
	}
	literals := func(joiner string) string {
		lines := wrap(encoded, 64)
		return `"-----BEGIN CERTIFICATE-----\n"` + joiner + `"` + strings.Join(lines, `\n"`+joiner+`"`) +
			`\n"` + joiner + `"-----END CERTIFICATE-----\n"`
	}
	other := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not one of ours")})

	tests := []struct {
		name string
		data string
		want bool
	}{
		{"der in a binary", "\x00\x01" + string(root.DER) + "\x00", true},
		{"pem with 64-character lines", pemWith(64, "\n", ""), true},
		{"pem with 72-character crlf lines (node.js)", "\x00" + pemWith(72, "\r\n", "") + "\x00", true},
		{"indented pem (yaml)", "ca: |\n" + pemWith(64, "\n", "    "), true},
		{"javascript string concatenation", "const ca = " + literals(" +\n  ") + ";", true},
		{"c adjacent string literals", "static const char *root =\n" + literals("\n") + ";", true},
		{"another certificate", string(other), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			matches := certdb.Find([]byte(test.data), certificates)
			if got := len(matches) == 1 && matches[0].SHA256 == root.SHA256; got != test.want {
				t.Errorf("Find matched %v, want a match: %t", matches, test.want)
			}
		})
	}
}
