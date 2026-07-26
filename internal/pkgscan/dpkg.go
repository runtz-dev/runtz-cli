package pkgscan

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

var sourceFieldPattern = regexp.MustCompile(`^([^\s(]+)(?:\s+\(([^)]+)\))?$`)

func parseDpkgStatus(reader io.Reader) ([]Package, error) {
	stanzas, err := parseDebianControl(reader)
	if err != nil {
		return nil, err
	}

	packages := make([]Package, 0, len(stanzas))
	for _, fields := range stanzas {
		if !strings.Contains(fields["Status"], "install ok installed") {
			continue
		}

		name := strings.TrimSpace(fields["Package"])
		version := strings.TrimSpace(fields["Version"])
		if name == "" || version == "" {
			continue
		}

		sourceName, sourceVersion := parseSourceField(fields["Source"], name, version)
		packages = append(packages, Package{
			Name:          name,
			Version:       version,
			Architecture:  strings.TrimSpace(fields["Architecture"]),
			SourceName:    sourceName,
			SourceVersion: sourceVersion,
			Manager:       "dpkg",
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

func parseDebianControl(reader io.Reader) ([]map[string]string, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	var stanzas []map[string]string
	current := make(map[string]string)
	lastKey := ""

	flush := func() {
		if len(current) == 0 {
			return
		}
		stanzas = append(stanzas, current)
		current = make(map[string]string)
		lastKey = ""
	}

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}

		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if lastKey != "" {
				current[lastKey] += "\n" + strings.TrimSpace(line)
			}
			continue
		}

		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("invalid dpkg status line: %q", line)
		}
		lastKey = strings.TrimSpace(key)
		current[lastKey] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	flush()

	return stanzas, nil
}

func parseSourceField(source, packageName, packageVersion string) (string, string) {
	source = strings.TrimSpace(source)
	if source == "" {
		return packageName, packageVersion
	}

	matches := sourceFieldPattern.FindStringSubmatch(source)
	if len(matches) == 0 {
		return source, packageVersion
	}

	sourceName := matches[1]
	sourceVersion := packageVersion
	if matches[2] != "" {
		sourceVersion = matches[2]
	}

	return sourceName, sourceVersion
}
