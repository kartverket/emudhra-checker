package registry_test

import (
	"strings"
	"testing"

	"github.com/kartverket/emudhra-checker/internal/registry"
)

func TestCanonicalName(t *testing.T) {
	t.Parallel()
	digest := "sha256:" + strings.Repeat("a", 64)
	tests := []struct {
		reference string
		want      string
	}{
		{"nginx", "index.docker.io/library/nginx:latest"},
		{"docker.io/library/nginx:latest", "index.docker.io/library/nginx:latest"},
		{"ghcr.io/org/app:v1@" + digest, "ghcr.io/org/app@" + digest},
		{"ghcr.io/org/app@" + digest, "ghcr.io/org/app@" + digest},
		{"Not A Reference", "Not A Reference"},
	}
	for _, test := range tests {
		t.Run(test.reference, func(t *testing.T) {
			t.Parallel()
			if got := registry.CanonicalName(test.reference); got != test.want {
				t.Errorf("CanonicalName(%q) = %q, want %q", test.reference, got, test.want)
			}
		})
	}
}
