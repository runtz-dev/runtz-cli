package sca

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type csprojFile struct {
	ItemGroups []struct {
		PackageReferences []struct {
			Include        string `xml:"Include,attr"`
			VersionAttr    string `xml:"Version,attr"`
			VersionElement string `xml:"Version"`
		} `xml:"PackageReference"`
	} `xml:"ItemGroup"`
}

// readCsproj parses NuGet PackageReference entries from a .NET .csproj file.
func readCsproj(path string) (string, []Dependency, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("read csproj: %w", err)
	}

	var project csprojFile
	if err := xml.Unmarshal(content, &project); err != nil {
		return "", nil, fmt.Errorf("parse csproj: %w", err)
	}

	var dependencies []Dependency
	for _, group := range project.ItemGroups {
		for _, reference := range group.PackageReferences {
			if reference.Include == "" {
				continue
			}

			version := strings.TrimSpace(reference.VersionAttr)
			if version == "" {
				version = strings.TrimSpace(reference.VersionElement)
			}

			dependencies = append(dependencies, Dependency{
				Name:            reference.Include,
				RequestedRange:  version,
				ResolvedVersion: normalizeVersion(version),
				Scope:           "dependencies",
				Ecosystem:       "nuget",
			})
		}
	}

	projectName := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	return projectName, dependencies, nil
}
