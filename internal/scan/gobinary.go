package scan

import (
	"bytes"
	"debug/buildinfo"
)

// Go 1.26.10 and 1.27.3 added the compromised intermediate keys to
// crypto/x509's distrusted SPKI list, so binaries built with them reject the
// keys whatever the image's CA bundle contains (see fixed-versions.json).
// goScheme compares Go versions per minor release line, such as 1.27.
func goScheme() versionScheme {
	return versionScheme{kind: KindGo, parse: parseGoVersion, line: majorMinorLine}
}

func detectGoBinary(file string, data []byte) (Component, bool) {
	version, ok := goBinaryVersion(data)
	if !ok {
		return Component{}, false
	}
	status, fixed := goScheme().status(version)
	return Component{Kind: KindGo, Path: file, Version: version, Status: status, Fixed: fixed}, true
}

// goBinaryVersion returns the Go toolchain version recorded in a Go
// executable. Stripped binaries keep the version. Packed binaries (UPX) do
// not.
func goBinaryVersion(data []byte) (string, bool) {
	info, err := buildinfo.Read(bytes.NewReader(data))
	if err != nil {
		return "", false
	}
	return info.GoVersion, true
}
