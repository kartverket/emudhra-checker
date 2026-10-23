// Package report writes scan results as a table, CSV or JSON.
package report

import (
	"cmp"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/kartverket/emudhra-checker/internal/scan"
)

// Sort orders results by cluster, namespace, application name, image and kind.
func Sort(results []scan.ImageResult) {
	slices.SortStableFunc(results, func(a, b scan.ImageResult) int {
		return cmp.Or(
			strings.Compare(a.Cluster, b.Cluster),
			strings.Compare(a.Namespace, b.Namespace),
			strings.Compare(a.Application, b.Application),
			strings.Compare(a.Image, b.Image),
			strings.Compare(a.Kind, b.Kind),
		)
	})
}

// WriteTable writes one aligned row per result.
func WriteTable(w io.Writer, results []scan.ImageResult) {
	headers := []string{
		"cluster",
		"namespace",
		"kind",
		"application name",
		"image name",
		"vulnerability status",
		"components",
		"mitigation",
	}
	rows := make([][]string, 0, len(results))
	for _, result := range results {
		rows = append(rows, []string{
			orDash(result.Cluster),
			orDash(result.Namespace),
			orDash(result.Kind),
			orDash(result.Application),
			result.Image,
			result.Status,
			orDash(scan.Summary(result.Components)),
			orDash(result.Mitigation),
		})
	}
	widths := make([]int, len(headers))
	for index, header := range headers {
		widths[index] = len(header)
	}
	for _, row := range rows {
		for index, value := range row {
			widths[index] = max(widths[index], len(value))
		}
	}
	writeTableRow(w, headers, widths)
	separators := make([]string, len(widths))
	for index, width := range widths {
		separators[index] = strings.Repeat("-", width)
	}
	fmt.Fprintln(w, strings.Join(separators, "-+-"))
	for _, row := range rows {
		writeTableRow(w, row, widths)
	}
}

func writeTableRow(w io.Writer, row []string, widths []int) {
	cells := make([]string, len(row))
	for index, value := range row {
		cells[index] = value + strings.Repeat(" ", widths[index]-len(value))
	}
	fmt.Fprintln(w, strings.Join(cells, " | "))
}

func orDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

// WriteJSON writes one indented JSON object per result. The output is a
// stream of objects, not an array.
func WriteJSON(w io.Writer, results []scan.ImageResult) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	for _, result := range results {
		err := encoder.Encode(result)
		if err != nil {
			return fmt.Errorf("encode %s: %w", result.Image, err)
		}
	}
	return nil
}

// WriteCSV emits one row per image. Multi-valued columns are joined with "; ".
func WriteCSV(w io.Writer, results []scan.ImageResult) error {
	records := [][]string{{
		"cluster", "namespace", "kind", "application", "image", "status",
		"jvm_detected", "components", "outdated", "mitigation", "certificates", "paths", "error",
	}}
	for _, result := range results {
		var names, paths, outdated []string
		for _, component := range result.Components {
			if component.Status == scan.VersionOutdated {
				outdated = append(outdated, component.Path+" ("+component.Version+", fixed in "+component.Fixed+")")
			}
		}
		for _, finding := range result.Findings {
			if finding.Trust != scan.TrustTrusted {
				paths = append(paths, finding.Path+" ("+finding.Trust+")")
				continue
			}
			paths = append(paths, finding.Path)
			for _, cert := range finding.Certificates {
				if !slices.Contains(names, cert.Name) {
					names = append(names, cert.Name)
				}
			}
		}
		records = append(records, []string{
			result.Cluster,
			result.Namespace,
			result.Kind,
			result.Application,
			result.Image,
			result.Status,
			strconv.FormatBool(result.JVMDetected),
			scan.Summary(result.Components),
			strings.Join(outdated, "; "),
			result.Mitigation,
			strings.Join(names, "; "),
			strings.Join(paths, "; "),
			result.Error,
		})
	}
	return csv.NewWriter(w).WriteAll(records)
}
