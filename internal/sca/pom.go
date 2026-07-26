package sca

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"
)

type pomProject struct {
	ArtifactID   string          `xml:"artifactId"`
	Dependencies []pomDependency `xml:"dependencies>dependency"`
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

// readPomXML parses direct dependencies from a Maven pom.xml. Versions that
// use property interpolation such as ${jackson.version} are kept as the
// requested range but skipped in the advisory lookup.
func readPomXML(path string) (string, []Dependency, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("read pom.xml: %w", err)
	}

	var project pomProject
	if err := xml.Unmarshal(content, &project); err != nil {
		return "", nil, fmt.Errorf("parse pom.xml: %w", err)
	}

	var dependencies []Dependency
	for _, dependency := range project.Dependencies {
		if dependency.GroupID == "" || dependency.ArtifactID == "" {
			continue
		}

		scope := dependency.Scope
		if scope == "" {
			scope = "compile"
		}

		version := strings.TrimSpace(dependency.Version)
		resolved := ""
		if !strings.Contains(version, "${") {
			resolved = normalizeVersion(version)
		}

		dependencies = append(dependencies, Dependency{
			Name:            dependency.GroupID + ":" + dependency.ArtifactID,
			RequestedRange:  version,
			ResolvedVersion: resolved,
			Scope:           scope,
			Ecosystem:       "maven",
		})
	}

	return project.ArtifactID, dependencies, nil
}
