package sca

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

var (
	cargoSectionPattern    = regexp.MustCompile(`^\[([^\]]+)\]$`)
	cargoDependencyPattern = regexp.MustCompile(`^([A-Za-z0-9_-]+)\s*=\s*(.+)$`)
	cargoVersionPattern    = regexp.MustCompile(`version\s*=\s*"([^"]+)"`)
)

// readCargoToml parses [dependencies], [dev-dependencies] and
// [build-dependencies] from a Rust Cargo.toml.
func readCargoToml(path string) (string, []Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", nil, fmt.Errorf("read Cargo.toml: %w", err)
	}
	defer file.Close()

	projectName := ""
	section := ""
	var dependencies []Dependency

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if matches := cargoSectionPattern.FindStringSubmatch(line); matches != nil {
			section = matches[1]
			continue
		}

		if section == "package" && projectName == "" {
			if matches := cargoDependencyPattern.FindStringSubmatch(line); matches != nil && matches[1] == "name" {
				projectName = strings.Trim(strings.TrimSpace(matches[2]), `"`)
			}
			continue
		}

		scope := cargoScope(section)
		if scope == "" {
			continue
		}

		matches := cargoDependencyPattern.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		requested := extractCargoVersion(matches[2])
		if requested == "" {
			continue
		}

		dependencies = append(dependencies, Dependency{
			Name:            matches[1],
			RequestedRange:  requested,
			ResolvedVersion: normalizeVersion(requested),
			Scope:           scope,
			Ecosystem:       "rust",
		})
	}
	if err := scanner.Err(); err != nil {
		return "", nil, fmt.Errorf("read Cargo.toml: %w", err)
	}

	return projectName, dependencies, nil
}

func cargoScope(section string) string {
	switch section {
	case "dependencies":
		return "dependencies"
	case "dev-dependencies":
		return "dev-dependencies"
	case "build-dependencies":
		return "build-dependencies"
	}
	if strings.HasSuffix(section, ".dependencies") {
		return "dependencies"
	}
	return ""
}

func extractCargoVersion(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "{") {
		if matches := cargoVersionPattern.FindStringSubmatch(value); matches != nil {
			return matches[1]
		}
		return ""
	}
	return strings.Trim(value, `"`)
}
