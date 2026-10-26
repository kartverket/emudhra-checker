package scan

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestDetectNode(t *testing.T) {
	t.Parallel()
	release := func(version string) []byte {
		return []byte("\x00https://nodejs.org/download/release/v" + version + "/node-v" + version + ".tar.gz\x00")
	}
	tests := []struct {
		name  string
		file  string
		data  []byte
		found bool
		want  Component
	}{
		{
			"outdated node",
			"usr/local/bin/node",
			release("22.15.0"),
			true,
			Component{
				Kind:    KindNode,
				Path:    "usr/local/bin/node",
				Version: "v22.15.0",
				Status:  VersionOutdated,
				Fixed:   "22.23.4",
			},
		},
		{
			"fixed node", "usr/bin/nodejs", release("24.22.1"), true,
			Component{Kind: KindNode, Path: "usr/bin/nodejs", Version: "v24.22.1", Status: VersionFixed},
		},
		{"another executable with the url", "usr/local/bin/npx", release("22.15.0"), false, Component{}},
		{"node without release urls", "usr/local/bin/node", []byte("ELF"), false, Component{}},
		{
			"urls that disagree", "usr/local/bin/node",
			[]byte("/download/release/v22.15.0/node-v22.16.0.tar.gz"), false, Component{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, found := nodeDetector(v1.Config{})(test.file, test.data)
			if found != test.found || got != test.want {
				t.Errorf("detectNode = %+v, %t; want %+v, %t", got, found, test.want, test.found)
			}
		})
	}
}

func TestNodeTrustNote(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		config v1.Config
		want   string
	}{
		{"defaults", v1.Config{Env: []string{"NODE_VERSION=22.15.0"}}, ""},
		{
			"system ca bundle and extra certificates",
			v1.Config{
				Env: []string{
					"NODE_OPTIONS=--max-old-space-size=4096 --use-openssl-ca",
					"NODE_EXTRA_CA_CERTS=/etc/ssl/corp.pem",
				},
			},
			"uses the system CA bundle (--use-openssl-ca), adds the certificates in /etc/ssl/corp.pem (NODE_EXTRA_CA_CERTS)",
		},
		{
			"bundled store on the command line",
			v1.Config{Entrypoint: []string{"node", "--use-bundled-ca", "server.js"}},
			"uses its own CA store (--use-bundled-ca)",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := nodeTrustNote(test.config); got != test.want {
				t.Errorf("nodeTrustNote = %q, want %q", got, test.want)
			}
		})
	}
}
