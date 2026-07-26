package sca

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

var gemSpecPattern = regexp.MustCompile(`^ {4}([A-Za-z0-9._-]+) \(([^)]+)\)$`)

// readGemfileLock parses resolved gems from the specs section of a
// Gemfile.lock. Only top-level spec entries (4-space indent) are read; the
// deeper entries are their transitive requirements.
func readGemfileLock(path string) (string, []Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", nil, fmt.Errorf("read Gemfile.lock: %w", err)
	}
	defer file.Close()

	var dependencies []Dependency
	inSpecs := false

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if !strings.HasPrefix(line, " ") {
			inSpecs = false
			continue
		}
		if trimmed == "specs:" {
			inSpecs = true
			continue
		}
		if !inSpecs {
			continue
		}

		matches := gemSpecPattern.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		dependencies = append(dependencies, Dependency{
			Name:            matches[1],
			RequestedRange:  matches[2],
			ResolvedVersion: normalizeVersion(matches[2]),
			Scope:           "dependencies",
			Ecosystem:       "rubygems",
		})
	}
	if err := scanner.Err(); err != nil {
		return "", nil, fmt.Errorf("read Gemfile.lock: %w", err)
	}

	return "", dependencies, nil
}
