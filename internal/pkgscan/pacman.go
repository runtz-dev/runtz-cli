package pkgscan

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// parsePacmanLocal reads the Arch pacman database at
// <root>/var/lib/pacman/local: one directory per installed package holding a
// desc file with %NAME%, %VERSION%, %ARCH% and %BASE% sections.
func parsePacmanLocal(databaseDir string) ([]Package, error) {
	entries, err := os.ReadDir(databaseDir)
	if err != nil {
		return nil, fmt.Errorf("read pacman database: %w", err)
	}

	var packages []Package
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		content, err := os.ReadFile(filepath.Join(databaseDir, entry.Name(), "desc"))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("read pacman desc for %s: %w", entry.Name(), err)
		}

		if pkg, ok := packageFromPacmanDesc(string(content)); ok {
			packages = append(packages, pkg)
		}
	}

	sortPacmanPackages(packages)
	return packages, nil
}

// packagesFromPacmanDescFiles builds the inventory from pacman desc files
// reconstructed out of container image layers.
func packagesFromPacmanDescFiles(files map[string][]byte) ([]Package, error) {
	var packages []Package
	for path, content := range files {
		if !isPacmanDescPath(path) {
			continue
		}
		if pkg, ok := packageFromPacmanDesc(string(content)); ok {
			packages = append(packages, pkg)
		}
	}
	if len(packages) == 0 {
		return nil, fmt.Errorf("image does not contain a pacman database")
	}

	sortPacmanPackages(packages)
	return packages, nil
}

func packageFromPacmanDesc(content string) (Package, bool) {
	fields := parsePacmanDesc(content)
	name := fields["NAME"]
	version := fields["VERSION"]
	if name == "" || version == "" {
		return Package{}, false
	}

	return Package{
		Name:          name,
		Version:       version,
		Architecture:  fields["ARCH"],
		SourceName:    firstNonEmpty(fields["BASE"], name),
		SourceVersion: version,
		Manager:       "pacman",
	}, true
}

func sortPacmanPackages(packages []Package) {
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].Version < packages[j].Version
		}
		return packages[i].Name < packages[j].Name
	})
}

func parsePacmanDesc(content string) map[string]string {
	fields := make(map[string]string)
	section := ""
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "%") && strings.HasSuffix(line, "%") && len(line) > 2 {
			section = strings.Trim(line, "%")
			continue
		}
		if line == "" || section == "" {
			continue
		}
		if _, exists := fields[section]; !exists {
			fields[section] = line
		}
	}
	return fields
}
