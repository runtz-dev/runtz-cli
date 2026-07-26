package sca

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

type composerJSON struct {
	Name       string            `json:"name"`
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}

// readComposerJSON parses require and require-dev packages from a PHP
// composer.json. Platform requirements such as php and ext-* are skipped.
func readComposerJSON(path string) (string, []Dependency, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("read composer.json: %w", err)
	}

	var manifest composerJSON
	if err := json.Unmarshal(content, &manifest); err != nil {
		return "", nil, fmt.Errorf("parse composer.json: %w", err)
	}

	var dependencies []Dependency
	dependencies = appendComposerDependencies(dependencies, manifest.Require, "require")
	dependencies = appendComposerDependencies(dependencies, manifest.RequireDev, "require-dev")

	sort.Slice(dependencies, func(i, j int) bool {
		return dependencies[i].Name < dependencies[j].Name
	})

	return manifest.Name, dependencies, nil
}

func appendComposerDependencies(dependencies []Dependency, source map[string]string, scope string) []Dependency {
	for name, requestedRange := range source {
		if !strings.Contains(name, "/") {
			continue
		}

		dependencies = append(dependencies, Dependency{
			Name:            name,
			RequestedRange:  requestedRange,
			ResolvedVersion: normalizeVersion(requestedRange),
			Scope:           scope,
			Ecosystem:       "composer",
		})
	}

	return dependencies
}
