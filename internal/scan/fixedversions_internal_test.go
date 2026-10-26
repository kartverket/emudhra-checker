package scan

import (
	"encoding/json"
	"testing"
)

func TestFixedVersionsData(t *testing.T) {
	t.Parallel()
	var data struct {
		Source  string              `json:"source"`
		Checked string              `json:"checked"`
		Fixed   map[string][]string `json:"fixed"`
	}
	if err := json.Unmarshal(fixedVersionsJSON, &data); err != nil {
		t.Fatal(err)
	}
	if data.Source == "" || data.Checked == "" {
		t.Error("fixed-versions.json must name its source and when it was checked")
	}
	for _, kind := range []string{KindGo, KindJDK, KindNode, KindCertifi, KindPip} {
		releases := data.Fixed[kind]
		if len(releases) == 0 {
			t.Errorf("no fixed releases for %s", kind)
		}
		for _, release := range releases {
			if _, ok := schemes()[kind].parse(release); !ok {
				t.Errorf("%s release %q does not parse", kind, release)
			}
		}
	}
}

func TestVersionStatus(t *testing.T) {
	t.Parallel()
	tests := []struct {
		kind, version, want, fixed string
	}{
		{KindJDK, "25.0.4.1", VersionOutdated, "25.0.5.0.2"},
		{KindJDK, "25.0.5.0.2", VersionFixed, ""},
		{KindJDK, "21.0.14", VersionFixed, ""},
		{KindJDK, "11.0.33", VersionOutdated, "11.0.33.0.2"},
		{
			KindJDK,
			"26.0.1",
			VersionOutdated,
			"8.0.511.32 / 11.0.33.0.2 / 17.0.21.0.2 / 21.0.13.0.2 / 25.0.5.0.2 / 27.0.1.0.2",
		},
		{KindJDK, "28", VersionFixed, ""},
		{KindJDK, "1.8.0_511-b32", VersionFixed, ""},
		{KindJDK, "1.8.0_511-b31", VersionOutdated, "8.0.511.32"},
		{KindJDK, "1.8.0_512-b04", VersionFixed, ""},
		{
			KindJDK,
			"1.7.0_80-b15",
			VersionOutdated,
			"8.0.511.32 / 11.0.33.0.2 / 17.0.21.0.2 / 21.0.13.0.2 / 25.0.5.0.2 / 27.0.1.0.2",
		},
		{KindNode, "v22.15.0", VersionOutdated, "22.23.4"},
		{KindNode, "22.23.4", VersionFixed, ""},
		{KindNode, "23.11.1", VersionOutdated, "22.23.4 / 24.22.1 / 26.12.1"},
		{KindNode, "20.19.0", VersionOutdated, "22.23.4 / 24.22.1 / 26.12.1"},
		{KindNode, "27.0.0", VersionFixed, ""},
		{KindCertifi, "2026.10.18", VersionOutdated, "2026.10.19"},
		{KindCertifi, "2026.10.19", VersionFixed, ""},
		{KindPip, "25.0.1", VersionOutdated, "26.2.2"},
		{KindPip, "26.3", VersionFixed, ""},
		{KindGo, "go1.27.2", VersionOutdated, "1.27.3"},
		{KindNode, "not a version", VersionUnknown, ""},
		{"unlisted", "1.0", VersionUnknown, ""},
	}
	for _, test := range tests {
		t.Run(test.kind+" "+test.version, func(t *testing.T) {
			t.Parallel()
			scheme, known := schemes()[test.kind]
			if !known {
				scheme = packageScheme(test.kind)
			}
			status, fixed := scheme.status(test.version)
			if status != test.want || fixed != test.fixed {
				t.Errorf(
					"versionStatus(%s, %q) = %s, %q; want %s, %q",
					test.kind,
					test.version,
					status,
					fixed,
					test.want,
					test.fixed,
				)
			}
		})
	}
}

// schemes returns the version scheme of every kind with fixed releases.
func schemes() map[string]versionScheme {
	return map[string]versionScheme{
		KindGo:      goScheme(),
		KindJDK:     jdkScheme(),
		KindNode:    nodeScheme(),
		KindCertifi: packageScheme(KindCertifi),
		KindPip:     packageScheme(KindPip),
	}
}
