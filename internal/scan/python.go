package scan

import "regexp"

// pythonPackageRE matches the files that name the version of an installed
// certifi or pip: the METADATA file in its dist-info directory, and the pip
// wheel that CPython bundles for ensurepip. CPython releases with a fix
// differ from older releases in this bundled pip.
var pythonPackageRE = regexp.MustCompile(
	`/(certifi|pip)-([^/-]+)\.dist-info/METADATA$|/ensurepip/_bundled/(pip)-([^/-]+)-py3-none-any\.whl$`,
)

// packageScheme compares the versions of a package with one fixed release.
func packageScheme(kind string) versionScheme {
	return versionScheme{kind: kind, parse: parseDottedVersion, line: 0}
}

// detectPythonPackage finds certifi and pip, which ship their own copy of the
// Mozilla roots.
func detectPythonPackage(file string, _ []byte) (Component, bool) {
	match := pythonPackageRE.FindStringSubmatch("/" + file)
	if match == nil {
		return Component{}, false
	}
	kind, version := match[1]+match[3], match[2]+match[4]
	status, fixed := packageScheme(kind).status(version)
	return Component{Kind: kind, Path: file, Version: version, Status: status, Fixed: fixed}, true
}
