package scan

import (
	"path"
	"regexp"
	"slices"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// nodeReleaseRE matches the source and headers URLs that each Node.js build
// stores for process.release, for example
// https://nodejs.org/download/release/v22.15.0/node-v22.15.0.tar.gz.
var nodeReleaseRE = regexp.MustCompile(`/download/release/v(\d+\.\d+\.\d+)/node-v(\d+\.\d+\.\d+)`)

// nodeScheme compares Node.js versions per major release line, such as 22.
func nodeScheme() versionScheme {
	return versionScheme{kind: KindNode, parse: parseDottedVersion, line: majorLine}
}

// nodeDetector finds a Node.js executable and its version. Node.js keeps its
// own copy of the Mozilla roots in the executable. An outdated Node.js thus
// trusts the compromised CAs also when the system CA bundle is fixed. The
// note tells how the image config sets up the CA store of Node.js.
func nodeDetector(config v1.Config) componentCheck {
	note := nodeTrustNote(config)
	return func(file string, data []byte) (Component, bool) {
		if base := path.Base(file); base != "node" && base != "nodejs" {
			return Component{}, false
		}
		match := nodeReleaseRE.FindSubmatch(data)
		if match == nil || string(match[1]) != string(match[2]) {
			return Component{}, false
		}
		version := "v" + string(match[1])
		status, fixed := nodeScheme().status(version)
		return Component{Kind: KindNode, Path: file, Version: version, Status: status, Fixed: fixed, Note: note}, true
	}
}

// nodeTrustNote describes how the image configures the CA store of Node.js.
// The --use-openssl-ca option makes Node.js use the system CA bundle instead
// of its own copy. NODE_EXTRA_CA_CERTS adds the certificates in a file.
func nodeTrustNote(config v1.Config) string {
	var options []string
	var notes []string
	for _, entry := range config.Env {
		name, value, _ := strings.Cut(entry, "=")
		switch name {
		case "NODE_OPTIONS":
			options = append(options, strings.Fields(value)...)
		case "NODE_EXTRA_CA_CERTS":
			notes = append(notes, "adds the certificates in "+value+" (NODE_EXTRA_CA_CERTS)")
		}
	}
	options = append(options, config.Entrypoint...)
	options = append(options, config.Cmd...)
	switch {
	case slices.Contains(options, "--use-openssl-ca"):
		notes = append([]string{"uses the system CA bundle (--use-openssl-ca)"}, notes...)
	case slices.Contains(options, "--use-bundled-ca"):
		notes = append([]string{"uses its own CA store (--use-bundled-ca)"}, notes...)
	}
	return strings.Join(notes, ", ")
}
