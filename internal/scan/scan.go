// Package scan finds distrusted certificates, JVMs and outdated Go binaries
// in container images.
package scan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/kartverket/emudhra-checker/internal/certdb"
	"github.com/kartverket/emudhra-checker/internal/inventory"
	"github.com/kartverket/emudhra-checker/internal/registry"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// errPull marks failures to download the image, as opposed to reading it.
var errPull = errors.New("cannot pull image")

// Image downloads one image, from the local Docker installation if local is
// set, and scans its final filesystem. Errors do not return: they set Status
// to ERR_DOCKER_PULL or UNKNOWN and fill Error.
func Image(
	ctx context.Context,
	target inventory.ImageTarget,
	certificates []certdb.DistrustedCertificate,
	local bool,
) ImageResult {
	result := newResult(target)
	err := inspectImage(ctx, &result, certificates, local)
	if err != nil {
		result.Error = strings.TrimSpace(err.Error())
		if errors.Is(err, errPull) {
			result.Status = StatusPullError
		}
	}
	return result
}

// fetch gets an image from its registry, or from the local Docker
// installation. The function it returns frees what the image holds.
func fetch(ctx context.Context, reference string, local bool) (v1.Image, func(), error) {
	if local {
		return registry.Local(ctx, reference)
	}
	image, err := registry.Fetch(ctx, reference)
	return image, func() {}, err
}

// inspectImage fills in result from the image. On error the status stays UNKNOWN.
func inspectImage(
	ctx context.Context,
	result *ImageResult,
	certificates []certdb.DistrustedCertificate,
	local bool,
) error {
	image, release, err := fetch(ctx, result.Image, local)
	if err != nil {
		return fmt.Errorf("%w: %w", errPull, err)
	}
	defer release()
	rawConfig, err := image.RawConfigFile()
	if err != nil {
		return fmt.Errorf("%w: fetch image config: %w", errPull, err)
	}
	config, err := v1.ParseConfigFile(bytes.NewReader(rawConfig))
	if err != nil {
		return fmt.Errorf("read image config: %w", err)
	}
	scan := newImageScan(config.Config, certificates)
	for _, found := range scan.configEvidence() {
		if found.jvm != "" {
			result.JVMEvidence = append(result.JVMEvidence, found.jvm)
		}
	}

	layers, err := image.Layers()
	if err != nil {
		return fmt.Errorf("read image layers: %w", err)
	}
	for _, layer := range layers {
		err = scan.scanImageLayer(layer, local)
		if err != nil {
			return err
		}
	}

	found := scan.collect()
	result.JVMEvidence = append([]string{}, found.jvm...)
	slices.Sort(result.JVMEvidence)
	result.JVMDetected = len(result.JVMEvidence) > 0
	result.Findings = append(result.Findings, found.findings...)
	result.JavaTrustStores = append(result.JavaTrustStores, found.trustStores...)
	result.Components = append(result.Components, found.components...)
	result.Mitigation = mitigation(result.Components)

	result.Status = StatusPatched
	if classifyTrust(result.Findings, found.caConf) {
		result.Status = trustedStatus(result.Components)
	}
	return nil
}
