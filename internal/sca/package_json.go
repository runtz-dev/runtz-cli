package sca

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type packageJSON struct {
	Name                 string            `json:"name"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

func ReadPackageJSON(path string) (string, []Dependency, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("read package json: %w", err)
	}

	var manifest packageJSON
	if err := json.Unmarshal(content, &manifest); err != nil {
		return "", nil, fmt.Errorf("parse package json: %w", err)
	}

	projectName := strings.TrimSpace(manifest.Name)
	if projectName == "" {
		projectName = filepath.Base(filepath.Dir(path))
	}

	dependencies := make([]Dependency, 0)
	dependencies = appendDependencies(dependencies, manifest.Dependencies, "dependencies")
	dependencies = appendDependencies(dependencies, manifest.DevDependencies, "devDependencies")
	dependencies = appendDependencies(dependencies, manifest.OptionalDependencies, "optionalDependencies")
	dependencies = appendDependencies(dependencies, manifest.PeerDependencies, "peerDependencies")

	sort.Slice(dependencies, func(i, j int) bool {
		if dependencies[i].Name == dependencies[j].Name {
			return dependencies[i].Scope < dependencies[j].Scope
		}

		return dependencies[i].Name < dependencies[j].Name
	})

	return projectName, dependencies, nil
}

func appendDependencies(dependencies []Dependency, source map[string]string, scope string) []Dependency {
	for name, requestedRange := range source {
		dependencies = append(dependencies, Dependency{
			Name:            name,
			RequestedRange:  requestedRange,
			ResolvedVersion: normalizeVersion(requestedRange),
			Scope:           scope,
			Ecosystem:       "npm",
		})
	}

	return dependencies
}

func normalizeVersion(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "npm:")

	versionPattern := regexp.MustCompile(`v?([0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?)`)
	matches := versionPattern.FindStringSubmatch(value)
	if len(matches) < 2 {
		return ""
	}

	return matches[1]
}
