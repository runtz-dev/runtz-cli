package pkgscan

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

func parseOSRelease(reader io.Reader) (OSRelease, error) {
	values := make(map[string]string)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[key] = unquoteOSReleaseValue(value)
	}
	if err := scanner.Err(); err != nil {
		return OSRelease{}, err
	}

	return OSRelease{
		ID:              strings.ToLower(values["ID"]),
		IDLike:          strings.ToLower(values["ID_LIKE"]),
		Name:            values["NAME"],
		PrettyName:      values["PRETTY_NAME"],
		VersionID:       values["VERSION_ID"],
		Version:         values["VERSION"],
		VersionCodename: firstNonEmpty(values["VERSION_CODENAME"], values["UBUNTU_CODENAME"]),
	}, nil
}

func unquoteOSReleaseValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		if unquoted, err := strconv.Unquote(value); err == nil {
			return unquoted
		}
	}
	return value
}

// packageFamily identifies which package database a distribution uses.
type packageFamily string

const (
	familyDpkg   packageFamily = "dpkg"
	familyRPM    packageFamily = "rpm"
	familyAPK    packageFamily = "apk"
	familyPacman packageFamily = "pacman"
	familyBrew   packageFamily = "brew"
)

// familyForOS resolves the package database family from os-release. The ID is
// checked first, then ID_LIKE so derivatives (Mint, Manjaro, Rocky, ...) map
// to their parent family.
func familyForOS(osRelease OSRelease) (packageFamily, error) {
	candidates := append([]string{osRelease.ID}, strings.Fields(osRelease.IDLike)...)
	for _, id := range candidates {
		switch id {
		case "debian", "ubuntu":
			return familyDpkg, nil
		case "alpine":
			return familyAPK, nil
		case "arch", "archlinux":
			return familyPacman, nil
		case "rhel", "centos", "fedora", "rocky", "almalinux", "ol", "amzn", "opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles", "sled", "suse", "mageia":
			return familyRPM, nil
		}
	}
	return "", fmt.Errorf("unsupported distribution %q (supported families: Debian/Ubuntu, RPM, Alpine and Arch based)", firstNonEmpty(osRelease.ID, osRelease.PrettyName))
}

// ecosystemForOS maps a distribution to its OSV ecosystem identifier. An
// empty result means OSV has no advisory feed for the distribution, so the
// scan sends the package inventory without CVE matching.
func ecosystemForOS(osRelease OSRelease) string {
	switch osRelease.ID {
	case "ubuntu":
		if osRelease.VersionID == "" {
			return ""
		}
		ecosystem := "Ubuntu:" + osRelease.VersionID
		if isUbuntuLTS(osRelease) {
			ecosystem += ":LTS"
		}
		return ecosystem
	case "debian":
		if osRelease.VersionID == "" {
			return ""
		}
		major, _, _ := strings.Cut(osRelease.VersionID, ".")
		if major == "" {
			return ""
		}
		return "Debian:" + major
	case "alpine":
		majorMinor := alpineMajorMinor(osRelease.VersionID)
		if majorMinor == "" {
			return ""
		}
		return "Alpine:v" + majorMinor
	case "rocky":
		return "Rocky Linux"
	case "almalinux":
		return "AlmaLinux"
	case "rhel", "centos":
		return "Red Hat"
	case "opensuse", "opensuse-leap", "opensuse-tumbleweed":
		return "openSUSE"
	case "sles", "sled":
		return "SUSE"
	case "mageia":
		return "Mageia"
	default:
		return ""
	}
}

func alpineMajorMinor(versionID string) string {
	parts := strings.Split(strings.TrimSpace(versionID), ".")
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "." + parts[1]
}

func isUbuntuLTS(osRelease OSRelease) bool {
	if strings.Contains(strings.ToUpper(osRelease.Version), "LTS") ||
		strings.Contains(strings.ToUpper(osRelease.PrettyName), "LTS") {
		return true
	}

	switch osRelease.VersionID {
	case "14.04", "16.04", "18.04", "20.04", "22.04", "24.04", "26.04":
		return true
	default:
		return false
	}
}

func osDisplayName(osRelease OSRelease) string {
	return firstNonEmpty(osRelease.PrettyName, osRelease.Name, osRelease.ID)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
