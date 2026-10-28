package registry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// Local exports an image from the local Docker installation with the docker
// CLI, which respects the active Docker context. The export goes to a
// temporary file, which release removes.
func Local(ctx context.Context, reference string) (v1.Image, func(), error) {
	file, err := os.CreateTemp("", "emudhra-checker-*.tar")
	if err != nil {
		return nil, nil, fmt.Errorf("create export file: %w", err)
	}
	release := func() { _ = os.Remove(file.Name()) }

	var stderr strings.Builder
	// "--" stops a reference that starts with "-" from being read as a flag.
	command := exec.CommandContext(ctx, "docker", "image", "save", "--", reference)
	command.Stdout, command.Stderr = file, &stderr
	err = errors.Join(command.Run(), file.Close())
	if err != nil {
		release()
		if message := strings.TrimSpace(stderr.String()); message != "" {
			err = errors.New(message)
		}
		return nil, nil, fmt.Errorf("docker image save: %w", err)
	}

	image, err := tarball.ImageFromPath(file.Name(), nil)
	if err != nil {
		release()
		return nil, nil, fmt.Errorf("read docker image save output: %w", err)
	}
	return image, release, nil
}
