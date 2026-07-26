package sca

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// readGoMod parses require directives from a go.mod file.
func readGoMod(path string) (string, []Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", nil, fmt.Errorf("read go.mod: %w", err)
	}
	defer file.Close()

	moduleName := ""
	var dependencies []Dependency
	inRequireBlock := false

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		switch {
		case strings.HasPrefix(line, "module "):
			moduleName = strings.TrimSpace(strings.TrimPrefix(line, "module "))
			continue
		case strings.HasPrefix(line, "require ("):
			inRequireBlock = true
			continue
		case inRequireBlock && line == ")":
			inRequireBlock = false
			continue
		}

		entry := ""
		if inRequireBlock {
			entry = line
		} else if strings.HasPrefix(line, "require ") {
			entry = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		}
		if entry == "" || strings.HasPrefix(entry, "//") {
			continue
		}

		scope := "require"
		if strings.Contains(entry, "// indirect") {
			scope = "indirect"
		}
		if index := strings.Index(entry, "//"); index >= 0 {
			entry = strings.TrimSpace(entry[:index])
		}

		fields := strings.Fields(entry)
		if len(fields) < 2 {
			continue
		}

		dependencies = append(dependencies, Dependency{
			Name:            fields[0],
			RequestedRange:  fields[1],
			ResolvedVersion: normalizeVersion(fields[1]),
			Scope:           scope,
			Ecosystem:       "go",
		})
	}
	if err := scanner.Err(); err != nil {
		return "", nil, fmt.Errorf("read go.mod: %w", err)
	}

	projectName := ""
	if moduleName != "" {
		projectName = filepath.Base(moduleName)
	}

	return projectName, dependencies, nil
}
