package sca

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

var requirementPattern = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(==|>=|<=|~=|!=|>|<|===)?\s*(.*)$`)

// readRequirementsTxt parses a pip requirements.txt file. Only pinned
// versions (==) produce a resolved version for the advisory lookup.
func readRequirementsTxt(path string) (string, []Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", nil, fmt.Errorf("read requirements.txt: %w", err)
	}
	defer file.Close()

	var dependencies []Dependency
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if index := strings.Index(line, "#"); index > 0 {
			line = strings.TrimSpace(line[:index])
		}
		if index := strings.Index(line, ";"); index > 0 {
			line = strings.TrimSpace(line[:index])
		}

		matches := requirementPattern.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		requested := strings.TrimSpace(matches[3] + matches[4])
		resolved := ""
		if matches[3] == "==" || matches[3] == "===" {
			resolved = normalizeVersion(matches[4])
		}

		dependencies = append(dependencies, Dependency{
			Name:            strings.ToLower(matches[1]),
			RequestedRange:  requested,
			ResolvedVersion: resolved,
			Scope:           "dependencies",
			Ecosystem:       "pip",
		})
	}
	if err := scanner.Err(); err != nil {
		return "", nil, fmt.Errorf("read requirements.txt: %w", err)
	}

	return "", dependencies, nil
}
