package registry

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	memregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// staleKeychain hands out credentials for every registry.
type staleKeychain struct{}

func (staleKeychain) Resolve(authn.Resource) (authn.Authenticator, error) {
	return &authn.Basic{Username: "user", Password: "expired"}, nil
}

// TestFetchImageFallsBackToAnonymous covers stored credentials that the
// registry refuses for an image anyone can pull.
func TestFetchImageFallsBackToAnonymous(t *testing.T) {
	t.Parallel()
	public := memregistry.New(memregistry.Logger(slog.NewLogLogger(slog.DiscardHandler, slog.LevelError)))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":[{"code":"DENIED","message":"denied"}]}`))
			return
		}
		public.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)

	ref, err := name.ParseReference(strings.TrimPrefix(server.URL, "http://") + "/team/app:v1")
	if err != nil {
		t.Fatal(err)
	}
	image, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	err = remote.Write(ref, image)
	if err != nil {
		t.Fatal(err)
	}

	_, err = fetchImage(t.Context(), ref.String(), staleKeychain{})
	if err != nil {
		t.Fatalf("fetchImage with refused credentials: %v", err)
	}
	_, err = fetchImage(t.Context(), ref.Context().String()+":missing", staleKeychain{})
	if err == nil || !strings.Contains(err.Error(), "DENIED") {
		t.Fatalf("want the original DENIED error when the anonymous retry fails too, got %v", err)
	}
}

func TestSelectManifest(t *testing.T) {
	t.Parallel()
	descriptor := func(os, architecture string) v1.Descriptor {
		return v1.Descriptor{Platform: &v1.Platform{OS: os, Architecture: architecture}}
	}
	tests := []struct {
		name      string
		manifests []v1.Descriptor
		want      string
	}{
		{"prefers amd64", []v1.Descriptor{descriptor("linux", "arm64"), descriptor("linux", "amd64")}, "amd64"},
		{"then arm64", []v1.Descriptor{descriptor("unknown", "unknown"), descriptor("linux", "arm64")}, "arm64"},
		{
			"then the first entry",
			[]v1.Descriptor{descriptor("linux", "s390x"), descriptor("linux", "ppc64le")},
			"s390x",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			selected, ok := selectManifest(test.manifests)
			if !ok || selected.Platform.Architecture != test.want {
				t.Errorf("selectManifest picked %v, want %s", selected.Platform, test.want)
			}
		})
	}
	if _, ok := selectManifest(nil); ok {
		t.Error("selectManifest found a manifest in an empty index")
	}
}
