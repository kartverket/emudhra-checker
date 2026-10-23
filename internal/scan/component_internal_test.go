package scan

import "testing"

// componentOf returns the component of kind that the scan found in file.
func componentOf(s *imageScan, file, kind string) Component {
	for _, component := range s.collect().components {
		if component.Path == file && component.Kind == kind {
			return component
		}
	}
	return Component{}
}

// trustStoreAt returns the Java trust store that the scan found at file.
func trustStoreAt(s *imageScan, file string) JavaTrustStore {
	for _, store := range s.collect().trustStores {
		if store.Path == file {
			return store
		}
	}
	return JavaTrustStore{}
}

func TestSummary(t *testing.T) {
	t.Parallel()
	component := func(kind, status string) Component { return Component{Kind: kind, Status: status} }
	tests := []struct {
		name       string
		components []Component
		want       string
	}{
		{"nothing found", nil, ""},
		{"all fixed", []Component{component(KindGo, VersionFixed), component(KindGo, VersionFixed)}, "go:fixed"},
		{
			"unknown beats fixed",
			[]Component{component(KindGo, VersionFixed), component(KindGo, VersionUnknown)},
			"go:unknown",
		},
		{
			"outdated beats everything, per kind",
			[]Component{
				component("jdk", VersionFixed),
				component(KindGo, VersionUnknown),
				component(KindGo, VersionOutdated),
			},
			"go:outdated jdk:fixed",
		},
		{"blocked.certs is the mitigation", []Component{component(KindBlockedCerts, BlockedPartial)}, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := Summary(test.components); got != test.want {
				t.Errorf("Summary = %q, want %q", got, test.want)
			}
		})
	}
}
