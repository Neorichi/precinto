package doctor

import (
	"regexp"
	"strconv"
	"strings"
)

// version is a semantic version as harnesses print it (2.1.329,
// 0.154.0-alpha.2). Build metadata is ignored.
type version struct {
	major, minor, patch int
	pre                 string // "" for a release
}

var versionRE = regexp.MustCompile(`^v?(\d{1,6})\.(\d{1,6})\.(\d{1,6})(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$`)

// parseVersion parses a whole string as a version.
func parseVersion(s string) (version, bool) {
	m := versionRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return version{}, false
	}
	var v version
	v.major, _ = strconv.Atoi(m[1])
	v.minor, _ = strconv.Atoi(m[2])
	v.patch, _ = strconv.Atoi(m[3])
	v.pre = m[4]
	return v, true
}

func (v version) String() string {
	s := strconv.Itoa(v.major) + "." + strconv.Itoa(v.minor) + "." + strconv.Itoa(v.patch)
	if v.pre != "" {
		s += "-" + v.pre
	}
	return s
}

// compare orders versions; a pre-release sorts before its release
// (pre-release identifiers compare as strings, which is enough here).
func (v version) compare(o version) int {
	for _, d := range []int{v.major - o.major, v.minor - o.minor, v.patch - o.patch} {
		if d != 0 {
			if d < 0 {
				return -1
			}
			return 1
		}
	}
	switch {
	case v.pre == o.pre:
		return 0
	case v.pre == "":
		return 1
	case o.pre == "":
		return -1
	case v.pre < o.pre:
		return -1
	}
	return 1
}

// inRange reports whether v satisfies every comparator of a range such as
// ">=0.154.0 <0.155.0" (the verified_versions syntax of the inventories).
// As in npm, a pre-release satisfies a range only when a comparator names
// a pre-release of the same major.minor.patch (0.155.0-alpha.1 is not in
// ">=0.154.0 <0.155.0": it is not a verified release). ok is false when
// the range does not parse.
func inRange(v version, r string) (in, ok bool) {
	fields := strings.Fields(r)
	if len(fields) == 0 {
		return false, false
	}
	in = true
	preAllowed := v.pre == ""
	for _, f := range fields {
		op := strings.TrimRight(f, "0123456789.-+abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
		bound, okb := parseVersion(f[len(op):])
		if !okb {
			return false, false
		}
		if bound.pre != "" && bound.major == v.major && bound.minor == v.minor && bound.patch == v.patch {
			preAllowed = true
		}
		c := v.compare(bound)
		switch op {
		case ">=":
			in = in && c >= 0
		case ">":
			in = in && c > 0
		case "<=":
			in = in && c <= 0
		case "<":
			in = in && c < 0
		case "=", "==", "":
			in = in && c == 0
		default:
			return false, false
		}
	}
	return in && preAllowed, true
}
