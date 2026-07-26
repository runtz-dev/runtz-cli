package pkgscan

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"

	// The blank import registers the pure-Go "sqlite" driver go-rpmdb uses to
	// read modern rpmdb.sqlite databases.
	_ "github.com/glebarez/go-sqlite"
	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
)

const rpmQueryFormat = `%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n`

var sourceRPMPattern = regexp.MustCompile(`^(.+)-[^-]+-[^-]+\.src\.rpm$`)

// rpmDatabasePaths are the rpm database locations checked inside container
// images, newest formats first (SQLite, then ndb, then BerkeleyDB).
var rpmDatabasePaths = []string{
	"var/lib/rpm/rpmdb.sqlite",
	"var/lib/rpm/Packages.db",
	"var/lib/rpm/Packages",
	"usr/lib/sysimage/rpm/rpmdb.sqlite",
	"usr/lib/sysimage/rpm/Packages.db",
	"usr/lib/sysimage/rpm/Packages",
}

// parseRPMDatabase reads an rpm database extracted from a container image.
// go-rpmdb opens files from disk, so the layer content goes through a
// temporary file.
func parseRPMDatabase(content []byte) ([]Package, error) {
	tempFile, err := os.CreateTemp("", "runtz-rpmdb-*")
	if err != nil {
		return nil, fmt.Errorf("create temporary rpm database: %w", err)
	}
	defer os.Remove(tempFile.Name())

	if _, err := tempFile.Write(content); err != nil {
		tempFile.Close()
		return nil, fmt.Errorf("write temporary rpm database: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return nil, fmt.Errorf("close temporary rpm database: %w", err)
	}

	database, err := rpmdb.Open(tempFile.Name())
	if err != nil {
		return nil, fmt.Errorf("open rpm database: %w", err)
	}
	defer database.Close()

	infos, err := database.ListPackages()
	if err != nil {
		return nil, fmt.Errorf("list rpm packages: %w", err)
	}

	packages := make([]Package, 0, len(infos))
	for _, info := range infos {
		if info == nil || info.Name == "" || info.Version == "" || info.Name == "gpg-pubkey" {
			continue
		}

		fullVersion := info.Version
		if info.Release != "" {
			fullVersion += "-" + info.Release
		}
		if info.Epoch != nil && *info.Epoch > 0 {
			fullVersion = fmt.Sprintf("%d:%s", *info.Epoch, fullVersion)
		}

		sourceName := info.Name
		if matches := sourceRPMPattern.FindStringSubmatch(info.SourceRpm); matches != nil {
			sourceName = matches[1]
		}

		packages = append(packages, Package{
			Name:          info.Name,
			Version:       fullVersion,
			Architecture:  info.Arch,
			SourceName:    sourceName,
			SourceVersion: fullVersion,
			Manager:       "rpm",
		})
	}

	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].Version < packages[j].Version
		}
		return packages[i].Name < packages[j].Name
	})

	return packages, nil
}

// listRPMPackages inventories an RPM-based system with the host's rpm binary,
// since the rpm database format (BerkeleyDB or SQLite) is not practical to
// read directly. --root is used when scanning a mounted root filesystem.
func listRPMPackages(ctx context.Context, root string) ([]Package, error) {
	rpmPath, err := exec.LookPath("rpm")
	if err != nil {
		return nil, fmt.Errorf("rpm binary not found: RPM-based scanning reads the package database with the host's rpm command")
	}

	args := []string{"-qa", "--queryformat", rpmQueryFormat}
	if root != "" && root != "/" {
		args = append([]string{"--root", root}, args...)
	}

	command := exec.CommandContext(ctx, rpmPath, args...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("run rpm -qa: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	return parseRPMQueryOutput(&stdout)
}

func parseRPMQueryOutput(reader *bytes.Buffer) ([]Package, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	var packages []Package
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\n")
		if strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) < 6 {
			continue
		}

		name, epoch, version, release, arch, sourceRPM := fields[0], fields[1], fields[2], fields[3], fields[4], fields[5]
		if name == "" || version == "" || name == "gpg-pubkey" {
			continue
		}

		fullVersion := version
		if release != "" && release != "(none)" {
			fullVersion += "-" + release
		}
		if epoch != "" && epoch != "0" && epoch != "(none)" {
			fullVersion = epoch + ":" + fullVersion
		}

		sourceName := name
		if matches := sourceRPMPattern.FindStringSubmatch(sourceRPM); matches != nil {
			sourceName = matches[1]
		}

		packages = append(packages, Package{
			Name:          name,
			Version:       fullVersion,
			Architecture:  arch,
			SourceName:    sourceName,
			SourceVersion: fullVersion,
			Manager:       "rpm",
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].Version < packages[j].Version
		}
		return packages[i].Name < packages[j].Name
	})

	return packages, nil
}
