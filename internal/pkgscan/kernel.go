package pkgscan

import (
	"cmp"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// debianKernelIDPattern pulls the kernel ABI out of Debian/Ubuntu per-kernel
// package names: "7.0.0-42" from linux-image-7.0.0-42-generic, or
// "6.12.43+deb13" from linux-headers-6.12.43+deb13-amd64.
var debianKernelIDPattern = regexp.MustCompile(`-(\d+\.\d+\.\d+(?:-\d+|\+[0-9a-z.]+))(?:-|$)`)

var kernelVersionFieldPattern = regexp.MustCompile(`[0-9]+|[A-Za-z]+`)

// kernelSelection records which installed kernel stays in CVE matching.
type kernelSelection struct {
	RunningRelease string   // uname -r of the booted kernel, when known
	Active         string   // kernel whose packages are matched against OSV
	Running        bool     // Active is the booted kernel, not a stand-in
	Newer          string   // newest installed kernel, when newer than Active
	Inactive       []string // other installed kernels, left out of CVE matching
	Skipped        int      // packages left out of CVE matching
}

// runningKernelRelease is the release of the booted kernel (uname -r). It is
// read even when --rootfs points elsewhere: a container scanning its host's
// root through a mount still shares the host kernel, and selectRunningKernel
// ignores a release that matches none of the scanned root's kernels.
func runningKernelRelease() string {
	content, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(content))
}

// selectRunningKernel drops the packages of installed-but-not-running kernels
// from CVE matching. Debian/Ubuntu and RPM distros keep several kernels side
// by side, and only the booted one is exposed: the others go away with
// "apt autoremove", not with a patch, so their CVEs are noise. When the
// running kernel is not among the installed ones (custom kernel, or --rootfs
// pointing at another system) the newest installed kernel stands in for it.
func selectRunningKernel(packages []Package, family packageFamily, runningRelease string) ([]Package, kernelSelection) {
	ids := kernelPackageIDs(packages, family)

	var kernels []string
	for _, id := range ids {
		if id != "" && !slices.Contains(kernels, id) {
			kernels = append(kernels, id)
		}
	}
	if len(kernels) < 2 {
		return packages, kernelSelection{}
	}
	slices.SortFunc(kernels, func(a, b string) int { return compareKernelIDs(b, a) })

	selection := kernelSelection{RunningRelease: runningRelease, Active: kernels[0]}
	if running := runningKernelID(kernels, family, runningRelease); running != "" {
		selection.Active = running
		selection.Running = true
		if running != kernels[0] {
			selection.Newer = kernels[0]
		}
	}

	for _, kernel := range kernels {
		if kernel != selection.Active {
			selection.Inactive = append(selection.Inactive, kernel)
		}
	}

	matched := make([]Package, 0, len(packages))
	for index, pkg := range packages {
		if ids[index] != "" && ids[index] != selection.Active {
			selection.Skipped++
			continue
		}
		matched = append(matched, pkg)
	}

	return matched, selection
}

// kernelPackageIDs returns, for each package, the kernel it belongs to, or ""
// for packages that are not tied to one kernel (linux-libc-dev,
// linux-image-generic, kernel-headers, ...).
func kernelPackageIDs(packages []Package, family packageFamily) []string {
	ids := make([]string, len(packages))
	switch family {
	case familyDpkg:
		for index, pkg := range packages {
			if !strings.HasPrefix(pkg.Name, "linux-") {
				continue
			}
			if matches := debianKernelIDPattern.FindStringSubmatch(pkg.Name); matches != nil {
				ids[index] = matches[1]
			}
		}
	case familyRPM:
		// RPM kernels keep the package name and differ by version, so only
		// kernel packages installed in more than one version are per-kernel;
		// single-version ones such as kernel-headers are left alone.
		versions := make(map[string]int)
		for _, pkg := range packages {
			if isRPMKernelPackage(pkg.Name) {
				versions[pkg.Name]++
			}
		}
		for index, pkg := range packages {
			if versions[pkg.Name] > 1 {
				ids[index] = stripEpoch(pkg.Version)
			}
		}
	}
	return ids
}

func isRPMKernelPackage(name string) bool {
	return name == "kernel" || strings.HasPrefix(name, "kernel-")
}

func stripEpoch(version string) string {
	if _, rest, ok := strings.Cut(version, ":"); ok {
		return rest
	}
	return version
}

// runningKernelID finds the installed kernel matching uname -r, preferring the
// longest match. Ubuntu runs 7.0.0-42 as 7.0.0-42-generic and RHEL runs
// 5.14.0-427.13.1.el9_4 as 5.14.0-427.13.1.el9_4.x86_64.
func runningKernelID(kernels []string, family packageFamily, release string) string {
	if release == "" {
		return ""
	}

	best := ""
	for _, kernel := range kernels {
		if hasPrefixAtBoundary(release, kernel) && len(kernel) > len(best) {
			best = kernel
		}
	}
	if best != "" || family != familyRPM {
		return best
	}

	// SUSE drops the build counter from uname -r: kernel-default
	// 5.14.21-150500.55.39.1 runs as 5.14.21-150500.55.39-default.
	for _, kernel := range kernels {
		cut := strings.LastIndex(kernel, ".")
		if cut > strings.Index(kernel, "-") && hasPrefixAtBoundary(release, kernel[:cut]) {
			return kernel
		}
	}
	return ""
}

func hasPrefixAtBoundary(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	return len(value) == len(prefix) || strings.ContainsRune("-.+", rune(value[len(prefix)]))
}

// compareKernelIDs orders kernel versions field by field, numbers compared as
// numbers. That is enough to pick the newest of a few installed kernels
// without a full dpkg or rpm version comparison.
func compareKernelIDs(a, b string) int {
	left := kernelVersionFieldPattern.FindAllString(a, -1)
	right := kernelVersionFieldPattern.FindAllString(b, -1)
	for index := 0; index < len(left) && index < len(right); index++ {
		leftNumber, leftErr := strconv.Atoi(left[index])
		rightNumber, rightErr := strconv.Atoi(right[index])
		result := strings.Compare(left[index], right[index])
		if leftErr == nil && rightErr == nil {
			result = cmp.Compare(leftNumber, rightNumber)
		}
		if result != 0 {
			return result
		}
	}
	return cmp.Compare(len(left), len(right))
}

func reportKernelSelection(progress func(string), selection kernelSelection) {
	if selection.Skipped == 0 {
		return
	}

	if selection.Running {
		reportProgress(progress, "Matching kernel CVEs against the running kernel %s only.", selection.Active)
	} else {
		reportProgress(progress, "Running kernel %q is not among the installed kernel packages; matching kernel CVEs against the newest installed kernel %s.", selection.RunningRelease, selection.Active)
	}
	reportProgress(progress, "Skipped CVE matching for %d packages of installed kernels that are not running: %s.", selection.Skipped, strings.Join(selection.Inactive, ", "))
	if selection.Newer != "" {
		reportProgress(progress, "Kernel %s is installed but not running yet; reboot to apply its fixes.", selection.Newer)
	}
}
