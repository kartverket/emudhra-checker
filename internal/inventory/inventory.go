// Package inventory reads cluster inventories: the images each cluster runs.
package inventory

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	targetColumns   = 3 // namespace, name, image; an optional 4th column is the Kubernetes kind
	namespaceColumn = "namespace"
)

// ImageTarget is one row of an input file: an image and the workload that
// runs it. Cluster is the name of the input file, without its extension.
type ImageTarget struct {
	Cluster     string
	Namespace   string
	Kind        string
	Application string
	Image       string
}

func isCSVHeader(row []string) bool {
	if len(row) < targetColumns {
		return false
	}
	header := make([]string, targetColumns)
	for index, column := range row[:targetColumns] {
		header[index] = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(column, "\ufeff")))
	}
	return (header[0] == namespaceColumn || header[0] == "kubernetes namespace") &&
		(header[1] == "application" || header[1] == "application name" || header[1] == "app") &&
		(header[2] == "image" || header[2] == "image name" || header[2] == "image reference")
}

// clusterName names the cluster after its input file: inputs/cluster-a.txt -> cluster-a.
func clusterName(imageFile string) string {
	if imageFile == "-" {
		return ""
	}
	base := filepath.Base(imageFile)
	return strings.TrimSuffix(base, filepath.Ext(base))
}

// Read returns the targets from the image references on the command line and
// the rows of the input files, in that order, without duplicates. The file
// name "-" reads standard input.
func Read(positionalImages []string, imageFiles []string) ([]ImageTarget, error) {
	targets := make([]ImageTarget, 0, len(positionalImages))
	for _, image := range positionalImages {
		image = strings.TrimSpace(image)
		if image != "" {
			targets = append(targets, ImageTarget{Image: image})
		}
	}

	for _, imageFile := range imageFiles {
		fileTargets, err := readTargetFile(imageFile)
		if err != nil {
			return nil, err
		}
		targets = append(targets, fileTargets...)
	}

	seen := make(map[ImageTarget]bool)
	unique := make([]ImageTarget, 0, len(targets))
	for _, target := range targets {
		if !seen[target] {
			seen[target] = true
			unique = append(unique, target)
		}
	}
	return unique, nil
}

func readTargetFile(imageFile string) ([]ImageTarget, error) {
	var source io.Reader = os.Stdin
	if imageFile != "-" {
		file, err := os.Open(imageFile)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		source = file
	}

	cluster := clusterName(imageFile)
	reader := csv.NewReader(source)
	reader.FieldsPerRecord = -1
	var targets []ImageTarget
	for {
		row, err := reader.Read()
		if errors.Is(err, io.EOF) {
			return targets, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%s: invalid CSV: %w", imageFile, err)
		}
		if skipRow(row) || (len(targets) == 0 && isCSVHeader(row)) {
			continue
		}
		target, err := parseTargetRow(row, cluster)
		if err != nil {
			line, _ := reader.FieldPos(0)
			return nil, fmt.Errorf("%s:%d: %w", imageFile, line, err)
		}
		targets = append(targets, target)
	}
}

// skipRow reports whether a row is blank or a # comment.
func skipRow(row []string) bool {
	for _, value := range row {
		if strings.TrimSpace(value) != "" {
			return strings.HasPrefix(strings.TrimSpace(row[0]), "#")
		}
	}
	return true
}

func parseTargetRow(row []string, cluster string) (ImageTarget, error) {
	if len(row) < targetColumns {
		return ImageTarget{}, errors.New("expected at least 3 CSV columns (namespace, application, image)")
	}
	target := ImageTarget{
		Cluster:     cluster,
		Namespace:   strings.TrimSpace(row[0]),
		Application: strings.TrimSpace(row[1]),
		Image:       strings.TrimSpace(row[2]),
	}
	if target.Namespace == "" || target.Application == "" || target.Image == "" {
		return ImageTarget{}, errors.New("namespace, application, and image must not be empty")
	}
	// The kind is free text, so any Kubernetes kind works: Deployment,
	// StatefulSet, CronJob or the kind of a custom resource.
	if len(row) > targetColumns {
		target.Kind = strings.TrimSpace(row[targetColumns])
	}
	return target, nil
}
