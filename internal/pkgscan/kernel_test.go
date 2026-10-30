package pkgscan

import (
	"slices"
	"testing"
)

func dpkgPackages(names ...string) []Package {
	packages := make([]Package, 0, len(names))
	for _, name := range names {
		packages = append(packages, Package{Name: name, Version: "1", Manager: "dpkg"})
	}
	return packages
}

func packageNames(packages []Package) []string {
	names := make([]string, 0, len(packages))
	for _, pkg := range packages {
		names = append(names, pkg.Name)
	}
	return names
}

func TestSelectRunningKernelDpkg(t *testing.T) {
	packages := dpkgPackages(
		"bash",
		"linux-headers-6.17.0-22-generic",
		"linux-hwe-6.17-headers-6.17.0-22",
		"linux-image-7.0.0-34-generic",
		"linux-modules-7.0.0-34-generic",
		"linux-image-7.0.0-38-generic",
		"linux-main-modules-zfs-7.0.0-38-generic",
		"linux-image-7.0.0-42-generic",
		"linux-modules-7.0.0-42-generic",
		"linux-headers-7.0.0-42",
		"linux-tools-7.0.0-42-generic",
		"linux-objects-nvidia-570-7.0.0-42-generic",
		"linux-image-generic",
		"linux-libc-dev",
		"linux-tools-common",
	)

	matched, selection := selectRunningKernel(packages, familyDpkg, "7.0.0-42-generic")

	expected := []string{
		"bash",
		"linux-image-7.0.0-42-generic",
		"linux-modules-7.0.0-42-generic",
		"linux-headers-7.0.0-42",
		"linux-tools-7.0.0-42-generic",
		"linux-objects-nvidia-570-7.0.0-42-generic",
		"linux-image-generic",
		"linux-libc-dev",
		"linux-tools-common",
	}
	if names := packageNames(matched); !slices.Equal(names, expected) {
		t.Fatalf("matched packages:\n got %v\nwant %v", names, expected)
	}
	if selection.Active != "7.0.0-42" || !selection.Running || selection.Newer != "" {
		t.Fatalf("unexpected selection: %+v", selection)
	}
	if selection.Skipped != 6 || !slices.Equal(selection.Inactive, []string{"7.0.0-38", "7.0.0-34", "6.17.0-22"}) {
		t.Fatalf("unexpected inactive kernels: %+v", selection)
	}
}

func TestSelectRunningKernelPendingReboot(t *testing.T) {
	packages := dpkgPackages("linux-image-7.0.0-38-generic", "linux-image-7.0.0-42-generic")

	matched, selection := selectRunningKernel(packages, familyDpkg, "7.0.0-38-generic")

	if names := packageNames(matched); !slices.Equal(names, []string{"linux-image-7.0.0-38-generic"}) {
		t.Fatalf("expected the running 7.0.0-38 kernel to stay, got %v", names)
	}
	if selection.Active != "7.0.0-38" || selection.Newer != "7.0.0-42" {
		t.Fatalf("expected a pending reboot into 7.0.0-42, got %+v", selection)
	}
}

func TestSelectRunningKernelFallsBackToNewest(t *testing.T) {
	packages := dpkgPackages("linux-image-6.8.0-9-generic", "linux-image-6.8.0-41-generic")

	for _, release := range []string{"", "6.8.12-custom", "6.8.0-4-generic"} {
		matched, selection := selectRunningKernel(packages, familyDpkg, release)
		if names := packageNames(matched); !slices.Equal(names, []string{"linux-image-6.8.0-41-generic"}) {
			t.Fatalf("release %q: expected the newest kernel, got %v", release, names)
		}
		if selection.Running {
			t.Fatalf("release %q: selection should not claim the running kernel: %+v", release, selection)
		}
	}
}

func TestSelectRunningKernelDebianTrixieNaming(t *testing.T) {
	packages := dpkgPackages(
		"linux-image-6.12.41+deb13-amd64",
		"linux-headers-6.12.41+deb13-common",
		"linux-image-6.12.43+deb13-amd64",
		"linux-headers-6.12.43+deb13-common",
		"linux-kbuild-6.12.43+deb13",
	)

	matched, selection := selectRunningKernel(packages, familyDpkg, "6.12.43+deb13-amd64")

	expected := []string{"linux-image-6.12.43+deb13-amd64", "linux-headers-6.12.43+deb13-common", "linux-kbuild-6.12.43+deb13"}
	if names := packageNames(matched); !slices.Equal(names, expected) {
		t.Fatalf("matched packages:\n got %v\nwant %v", names, expected)
	}
	if !selection.Running || selection.Skipped != 2 {
		t.Fatalf("unexpected selection: %+v", selection)
	}
}

func TestSelectRunningKernelSingleKernelIsUntouched(t *testing.T) {
	packages := dpkgPackages("bash", "linux-image-7.0.0-42-generic")

	matched, selection := selectRunningKernel(packages, familyDpkg, "6.1.0-1-amd64")

	if len(matched) != len(packages) || selection.Skipped != 0 {
		t.Fatalf("expected no filtering with a single kernel, got %v %+v", packageNames(matched), selection)
	}
}

func TestSelectRunningKernelRPM(t *testing.T) {
	packages := []Package{
		{Name: "kernel", Version: "5.14.0-427.13.1.el9_4"},
		{Name: "kernel", Version: "5.14.0-503.11.1.el9_5"},
		{Name: "kernel-core", Version: "5.14.0-427.13.1.el9_4"},
		{Name: "kernel-core", Version: "5.14.0-503.11.1.el9_5"},
		{Name: "kernel-headers", Version: "5.14.0-503.11.1.el9_5"},
		{Name: "kernel-tools", Version: "5.14.0-503.11.1.el9_5"},
		{Name: "openssl", Version: "1:3.0.7-27.el9"},
	}

	matched, selection := selectRunningKernel(packages, familyRPM, "5.14.0-427.13.1.el9_4.x86_64")

	expected := []Package{packages[0], packages[2], packages[4], packages[5], packages[6]}
	if !slices.Equal(matched, expected) {
		t.Fatalf("matched packages:\n got %v\nwant %v", matched, expected)
	}
	if selection.Active != "5.14.0-427.13.1.el9_4" || selection.Newer != "5.14.0-503.11.1.el9_5" {
		t.Fatalf("unexpected selection: %+v", selection)
	}
}

func TestSelectRunningKernelSUSE(t *testing.T) {
	packages := []Package{
		{Name: "kernel-default", Version: "5.14.21-150500.55.36.1"},
		{Name: "kernel-default", Version: "5.14.21-150500.55.39.1"},
	}

	_, selection := selectRunningKernel(packages, familyRPM, "5.14.21-150500.55.36-default")

	if selection.Active != "5.14.21-150500.55.36.1" || !selection.Running {
		t.Fatalf("expected the running SUSE kernel, got %+v", selection)
	}
}

func TestSelectRunningKernelIgnoresOtherFamilies(t *testing.T) {
	packages := []Package{{Name: "linux-lts", Version: "6.6.30-r0"}, {Name: "linux-lts", Version: "6.6.31-r0"}}

	matched, selection := selectRunningKernel(packages, familyAPK, "6.6.30-0-lts")

	if len(matched) != len(packages) || selection.Skipped != 0 {
		t.Fatalf("expected apk packages untouched, got %v %+v", matched, selection)
	}
}

func TestCompareKernelIDs(t *testing.T) {
	ordered := []string{"6.8.0-9", "6.8.0-41", "6.17.0-22", "7.0.0-38", "7.0.0-42", "7.0.0-42.1"}
	for index := 1; index < len(ordered); index++ {
		if compareKernelIDs(ordered[index-1], ordered[index]) >= 0 {
			t.Fatalf("expected %s < %s", ordered[index-1], ordered[index])
		}
		if compareKernelIDs(ordered[index], ordered[index-1]) <= 0 {
			t.Fatalf("expected %s > %s", ordered[index], ordered[index-1])
		}
	}
	if compareKernelIDs("5.14.0-427.13.1.el9_4", "5.14.0-427.13.1.el9_4") != 0 {
		t.Fatal("expected equal kernels to compare equal")
	}
}
