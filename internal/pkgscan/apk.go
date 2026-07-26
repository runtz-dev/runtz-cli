package pkgscan

import (
	"bufio"
	"io"
	"sort"
	"strings"
)

// parseApkInstalled parses the Alpine apk database at /lib/apk/db/installed.
// Entries are blank-line separated stanzas with single-letter keys:
// P (package), V (version), A (architecture), o (origin/source package).
func parseApkInstalled(reader io.Reader) ([]Package, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	var packages []Package
	current := make(map[string]string)

	flush := func() {
		name := current["P"]
		version := current["V"]
		if name != "" && version != "" {
			packages = append(packages, Package{
				Name:          name,
				Version:       version,
				Architecture:  current["A"],
				SourceName:    firstNonEmpty(current["o"], name),
				SourceVersion: version,
				Manager:       "apk",
			})
		}
		current = make(map[string]string)
	}

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		current[key] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	flush()

	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].Version < packages[j].Version
		}
		return packages[i].Name < packages[j].Name
	})

	return packages, nil
}
