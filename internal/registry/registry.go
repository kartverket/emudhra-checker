// Package registry fetches images from OCI registries with the user's
// Docker credentials, or from the local Docker installation.
package registry

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

const userAgent = "emudhra-checker-image-scanner/1.0"

// CanonicalName spells out an image reference in full, so that different
// spellings of the same image compare equal: nginx and
// index.docker.io/library/nginx:latest, or app:v1@sha256:... and app@sha256:...
// A reference that cannot be parsed is returned unchanged.
func CanonicalName(reference string) string {
	ref, err := name.ParseReference(reference)
	if err != nil {
		return reference
	}
	return ref.Name()
}

// Fetch resolves an image reference. Credentials come from the Docker config:
// docker login and the credential helpers that it names.
func Fetch(ctx context.Context, reference string) (v1.Image, error) {
	return fetchImage(ctx, reference, authn.DefaultKeychain)
}

// fetchImage resolves an image reference with the given credentials.
func fetchImage(ctx context.Context, reference string, keychain authn.Keychain) (v1.Image, error) {
	ref, err := name.ParseReference(reference)
	if err != nil {
		return nil, fmt.Errorf("parse image reference: %w", err)
	}
	options := []remote.Option{remote.WithContext(ctx), remote.WithUserAgent(userAgent)}
	descriptor, err := remote.Get(ref, append(options, remote.WithAuthFromKeychain(keychain))...)
	if isDenied(err) {
		// Credentials without access to the repository (a stale docker login, a
		// token without read:packages) are refused even for public images.
		if anonymous, anonymousErr := remote.Get(ref, options...); anonymousErr == nil {
			descriptor, err = anonymous, nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	if !descriptor.MediaType.IsIndex() {
		return descriptor.Image()
	}

	index, err := descriptor.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("read image index: %w", err)
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("read image index: %w", err)
	}
	selected, ok := selectManifest(manifest.Manifests)
	if !ok {
		return nil, errors.New("image index has no manifests")
	}
	return index.Image(selected.Digest)
}

func isDenied(err error) bool {
	var transportErr *transport.Error
	return errors.As(err, &transportErr) &&
		(transportErr.StatusCode == http.StatusUnauthorized || transportErr.StatusCode == http.StatusForbidden)
}

// selectManifest prefers linux/amd64, then linux/arm64, then the first entry.
func selectManifest(manifests []v1.Descriptor) (v1.Descriptor, bool) {
	if len(manifests) == 0 {
		return v1.Descriptor{}, false
	}
	for _, architecture := range []string{"amd64", "arm64"} {
		for _, candidate := range manifests {
			if candidate.Platform != nil && candidate.Platform.OS == "linux" &&
				candidate.Platform.Architecture == architecture {
				return candidate, true
			}
		}
	}
	return manifests[0], true
}
