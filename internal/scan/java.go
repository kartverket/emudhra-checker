package scan

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

var (
	trustStorePropertyRE = regexp.MustCompile(`-Djavax\.net\.ssl\.trustStore=([^\s"']+)`)
	javaStartupRE        = regexp.MustCompile(`(?i)(^|[/\s])java(?:w)?(?:\.exe)?($|[\s])`)
)

func isJavaRuntimePath(filename string) bool {
	normalized := strings.ToLower(strings.Trim(filename, "/"))
	base := path.Base(normalized)
	if base == "libjvm.so" || base == "jvm.dll" {
		return true
	}
	return (base == "java" || base == "java.exe" || base == "javaw.exe") &&
		strings.Contains("/"+normalized, "/bin/")
}

func isDefaultJavaTrustStore(filename string) bool {
	normalized := strings.ToLower(strings.Trim(filename, "/"))
	base := path.Base(normalized)
	if base != "cacerts" && base != "jssecacerts" {
		return false
	}
	return normalized == "etc/ssl/certs/java/cacerts" ||
		slices.Contains(strings.Split(normalized, "/"), "security")
}

// imageJavaSettings reads the image config. It returns the trust stores that
// -Djavax.net.ssl.trustStore configures, and evidence that the image starts a
// JVM.
func imageJavaSettings(config v1.Config) (map[string]bool, []string) {
	configured := make(map[string]bool)
	evidence := make([]string, 0)
	workingDir := config.WorkingDir
	if workingDir == "" {
		workingDir = "/"
	}

	configValues := append([]string{}, config.Env...)
	configValues = append(configValues, config.Entrypoint...)
	configValues = append(configValues, config.Cmd...)
	for _, value := range configValues {
		for _, match := range trustStorePropertyRE.FindAllStringSubmatch(value, -1) {
			storePath := match[1]
			if strings.Contains(storePath, "$") {
				evidence = append(evidence, "Unresolved Java trust-store setting: "+storePath)
				continue
			}
			if !strings.HasPrefix(storePath, "/") {
				storePath = path.Join(workingDir, storePath)
			}
			storePath = strings.TrimPrefix(path.Clean(storePath), "/")
			configured[storePath] = true
			evidence = append(evidence, "Configured Java trust store: "+storePath)
		}
	}

	for _, item := range append(append([]string{}, config.Entrypoint...), config.Cmd...) {
		if javaStartupRE.MatchString(item) {
			evidence = append(evidence, "Image startup command: "+item)
		}
	}
	return configured, evidence
}

// jdkScheme compares JDK versions per feature release, such as 21.
func jdkScheme() versionScheme {
	return versionScheme{kind: KindJDK, parse: parseJDKVersion, line: majorLine}
}

// jvmDetector finds signs of a JVM and the Java trust stores. The image config
// gives JVM start commands and -Djavax.net.ssl.trustStore settings. The final
// filesystem gives JVM runtime files, and the default and configured trust
// stores.
func jvmDetector(config v1.Config) detector {
	configured, settings := imageJavaSettings(config)
	image := make([]evidence, 0, len(settings))
	for _, line := range settings {
		image = append(image, evidence{jvm: line})
	}
	return detector{image: image, entry: func(entry fileEntry) []evidence {
		var found []evidence
		if isJavaRuntimePath(entry.path) {
			found = append(found, evidence{
				jvm: fmt.Sprintf("JVM runtime file: %s (layer %s)", entry.path, entry.layerDigest),
			})
		}
		if entry.regular && (configured[entry.path] || isDefaultJavaTrustStore(entry.path)) {
			found = append(found, evidence{trustStore: &JavaTrustStore{
				Path:         entry.path,
				LayerDigest:  entry.layerDigest,
				FileSHA256:   entry.fileSHA256,
				Certificates: entry.certificates,
			}})
		}
		return found
	}}
}

// detectJDK reads the release file in a JDK's home directory, which names its
// version. Java 8 needs the build number from JAVA_RUNTIME_VERSION: the fix
// is 8u511 b32.
func detectJDK(file string, data []byte) (Component, bool) {
	if path.Base(file) != "release" {
		return Component{}, false
	}
	values := make(map[string]string)
	for line := range strings.Lines(string(data)) {
		if key, value, found := strings.Cut(strings.TrimSpace(line), "="); found {
			values[key] = strings.Trim(value, `"`)
		}
	}
	javaVersion := values["JAVA_VERSION"]
	if javaVersion == "" {
		return Component{}, false
	}
	if runtimeVersion := values["JAVA_RUNTIME_VERSION"]; strings.HasPrefix(javaVersion, "1.8.0_") &&
		runtimeVersion != "" {
		javaVersion = runtimeVersion
	}
	status, fixed := jdkScheme().status(javaVersion)
	return Component{Kind: KindJDK, Path: file, Version: javaVersion, Status: status, Fixed: fixed}, true
}
