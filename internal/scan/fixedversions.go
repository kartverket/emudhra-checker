package scan

import (
	_ "embed" // fixed-versions.json
	"encoding/json"
	"go/version"
	"strconv"
	"strings"
)

// fixedVersionsJSON lists the first fixed release of each maintained line,
// from the incident's list of known patches.
//
//go:embed fixed-versions.json
var fixedVersionsJSON []byte

// Leading numbers that name a release line: Go 1.27, JDK 25, Node 22.
const (
	majorMinorLine = 2
	majorLine      = 1
)

// versionScheme tells how to compare the versions of one component kind with
// the fixed releases of that kind. Each detector brings its own scheme.
type versionScheme struct {
	kind  string
	parse func(string) ([]int, bool)
	line  int // leading numbers that name a release line, such as 1.27 for Go
}

// fixedReleases returns the fixed release of every line of a kind.
func fixedReleases(kind string) []string {
	var data struct {
		Fixed map[string][]string `json:"fixed"`
	}
	if err := json.Unmarshal(fixedVersionsJSON, &data); err != nil {
		return nil
	}
	return data.Fixed[kind]
}

// status compares a version with the fixed releases of the scheme's kind. A
// version is fixed from the fixed release of its line on, and when its line
// is newer than every listed line. A line without a fixed release is
// outdated. For an outdated version, it also returns the release to upgrade
// to.
func (scheme versionScheme) status(raw string) (string, string) {
	current, ok := scheme.parse(raw)
	releases := fixedReleases(scheme.kind)
	if !ok || len(releases) == 0 {
		return VersionUnknown, ""
	}
	newest := []int(nil)
	for _, release := range releases {
		fixed, valid := scheme.parse(release)
		if !valid {
			continue
		}
		if compareVersions(fixed[:min(scheme.line, len(fixed))], current[:min(scheme.line, len(current))]) == 0 {
			if compareVersions(current, fixed) >= 0 {
				return VersionFixed, ""
			}
			return VersionOutdated, release
		}
		if compareVersions(fixed, newest) > 0 {
			newest = fixed
		}
	}
	if compareVersions(current[:min(scheme.line, len(current))], newest[:min(scheme.line, len(newest))]) > 0 {
		return VersionFixed, ""
	}
	return VersionOutdated, strings.Join(releases, " / ")
}

// compareVersions compares numbers from left to right. A missing number
// counts as 0.
func compareVersions(a, b []int) int {
	for index := range max(len(a), len(b)) {
		x, y := 0, 0
		if index < len(a) {
			x = a[index]
		}
		if index < len(b) {
			y = b[index]
		}
		if x != y {
			return x - y
		}
	}
	return 0
}

// parseDottedVersion reads the leading dot-separated numbers of a version such
// as v22.15.0 or 2026.10.19.
func parseDottedVersion(raw string) ([]int, bool) {
	var numbers []int
	for part := range strings.SplitSeq(strings.TrimPrefix(strings.TrimSpace(raw), "v"), ".") {
		number, err := strconv.Atoi(part)
		if err != nil {
			break
		}
		numbers = append(numbers, number)
	}
	return numbers, len(numbers) > 0
}

// parseGoVersion reads go1.27.3 (or 1.27.3) as 1 27 3. A pre-release such as
// go1.27rc1 sorts before go1.27.0, and experiments after a space are ignored.
func parseGoVersion(raw string) ([]int, bool) {
	raw, _, _ = strings.Cut(raw, " ")
	if !strings.HasPrefix(raw, "go") {
		raw = "go" + raw
	}
	if !version.IsValid(raw) {
		return nil, false
	}
	release := strings.TrimPrefix(raw, "go")
	if index := strings.IndexAny(release, "rb"); index >= 0 {
		numbers, _ := parseDottedVersion(release[:index])
		return append(numbers, -1), true
	}
	return parseDottedVersion(release)
}

// parseJDKVersion reads both version schemes of the JDK release file:
// 25.0.4.1 as 25 0 4 1, and Java 8's 1.8.0_511-b32 as 8 0 511 32.
func parseJDKVersion(raw string) ([]int, bool) {
	raw = strings.Trim(strings.TrimSpace(raw), `"`)
	if rest, ok := strings.CutPrefix(raw, "1.8.0_"); ok {
		update, build, _ := strings.Cut(rest, "-b")
		prefix := []int{8, 0}
		numbers := prefix
		for _, part := range []string{update, build} {
			number, err := strconv.Atoi(strings.TrimRight(part, "+-abcdefghijklmnopqrstuvwxyz"))
			if err != nil {
				break
			}
			numbers = append(numbers, number)
		}
		return numbers, len(numbers) > len(prefix)
	}
	release, _, _ := strings.Cut(raw, "+")
	return parseDottedVersion(release)
}
