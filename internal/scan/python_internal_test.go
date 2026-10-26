package scan

import "testing"

func TestDetectPythonPackage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		file  string
		found bool
		want  Component
	}{
		{
			"usr/local/lib/python3.12/site-packages/certifi-2026.10.18.dist-info/METADATA", true,
			Component{
				Kind: KindCertifi, Path: "usr/local/lib/python3.12/site-packages/certifi-2026.10.18.dist-info/METADATA",
				Version: "2026.10.18", Status: VersionOutdated, Fixed: "2026.10.19",
			},
		},
		{
			"app/.venv/lib/python3.13/site-packages/pip-26.2.2.dist-info/METADATA", true,
			Component{
				Kind: KindPip, Path: "app/.venv/lib/python3.13/site-packages/pip-26.2.2.dist-info/METADATA",
				Version: "26.2.2", Status: VersionFixed,
			},
		},
		{
			"usr/local/lib/python3.12/ensurepip/_bundled/pip-25.0.1-py3-none-any.whl", true,
			Component{
				Kind: KindPip, Path: "usr/local/lib/python3.12/ensurepip/_bundled/pip-25.0.1-py3-none-any.whl",
				Version: "25.0.1", Status: VersionOutdated, Fixed: "26.2.2",
			},
		},
		{"usr/local/lib/python3.12/site-packages/certifi-2026.10.18.dist-info/RECORD", false, Component{}},
		{"usr/local/lib/python3.12/site-packages/requests-2.32.3.dist-info/METADATA", false, Component{}},
	}
	for _, test := range tests {
		t.Run(test.file, func(t *testing.T) {
			t.Parallel()
			got, found := detectPythonPackage(test.file, nil)
			if found != test.found || got != test.want {
				t.Errorf("detectPythonPackage = %+v, %t; want %+v, %t", got, found, test.want, test.found)
			}
		})
	}
}
