package report_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/kartverket/emudhra-checker/internal/report"

	"github.com/kartverket/emudhra-checker/internal/certdb"
	"github.com/kartverket/emudhra-checker/internal/scan"
)

func TestSort(t *testing.T) {
	t.Parallel()
	results := []scan.ImageResult{
		{Cluster: "b", Namespace: "a", Application: "a", Image: "a"},
		{Cluster: "a", Namespace: "b", Application: "a", Image: "a"},
		{Cluster: "a", Namespace: "a", Application: "b", Image: "a"},
		{Cluster: "a", Namespace: "a", Application: "a", Image: "b"},
		{Cluster: "a", Namespace: "a", Application: "a", Image: "a", Kind: "b"},
		{Cluster: "a", Namespace: "a", Application: "a", Image: "a", Kind: "a"},
	}
	report.Sort(results)
	got := make([]string, 0, len(results))
	for _, result := range results {
		got = append(got, result.Cluster+result.Namespace+result.Application+result.Image+result.Kind)
	}
	if want := []string{"aaaaa", "aaaab", "aaab", "aaba", "abaa", "baaa"}; !slices.Equal(got, want) {
		t.Fatalf("sorted order = %v, want %v", got, want)
	}
}

func TestWriteCSV(t *testing.T) {
	t.Parallel()
	root := certdb.CertificateMatch{Name: "Root, G1"}
	results := []scan.ImageResult{{
		Cluster: "c1", Namespace: "ns", Kind: "StatefulSet", Application: "app", Image: "img",
		Status: scan.StatusVulnerable, JVMDetected: true,
		Mitigation: "blocked.certs (partial: 16/48)",
		Components: []scan.Component{
			{Kind: scan.KindGo, Path: "bin/new", Version: "go1.27.3", Status: scan.VersionFixed},
			{
				Kind:    scan.KindGo,
				Path:    "bin/old",
				Version: "go1.25.4",
				Status:  scan.VersionOutdated,
				Fixed:   "1.26.10 / 1.27.3",
			},
		},
		Findings: []scan.Finding{
			{Path: "a.pem", Certificates: []certdb.CertificateMatch{root}, Trust: scan.TrustTrusted},
			{Path: "b.pem", Certificates: []certdb.CertificateMatch{root, {Name: "Sub"}}, Trust: scan.TrustTrusted},
			{Path: "c.pem", Certificates: []certdb.CertificateMatch{root}, Trust: scan.TrustDistrusted},
		},
	}}
	var output bytes.Buffer
	if err := report.WriteCSV(&output, results); err != nil {
		t.Fatal(err)
	}
	want := "cluster,namespace,kind,application,image,status,jvm_detected,components,outdated,mitigation,certificates,paths,error\n" +
		"c1,ns,StatefulSet,app,img,VULNERABLE,true,go:outdated,\"bin/old (go1.25.4, fixed in 1.26.10 / 1.27.3)\",blocked.certs (partial: 16/48),\"Root, G1; Sub\",a.pem; b.pem; c.pem (distrusted),\n"
	if output.String() != want {
		t.Fatalf("report.WriteCSV output:\n%s\nwant:\n%s", output.String(), want)
	}
}
