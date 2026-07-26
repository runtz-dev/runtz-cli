package sca

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/runtz-dev/runtz-cli/internal/version"
)

var ScannerVersion = version.Scanner()

type Options struct {
	Path        string
	ProjectName string
	Source      string
	GitHubToken string
	Progress    func(string)
}

func Run(ctx context.Context, options Options) (Result, error) {
	target := strings.TrimSpace(options.Path)
	if target == "" {
		target = "."
	}

	absolutePath, err := filepath.Abs(target)
	if err != nil {
		return Result{}, fmt.Errorf("resolve scan path: %w", err)
	}

	info, err := os.Stat(absolutePath)
	if err != nil {
		return Result{}, fmt.Errorf("read scan path: %w", err)
	}

	var manifests []string
	root := absolutePath
	if info.IsDir() {
		manifests, err = discoverManifests(absolutePath)
		if err != nil {
			return Result{}, err
		}
		if len(manifests) == 0 {
			return Result{}, fmt.Errorf("no supported dependency manifests found under %s (supported: %s)", absolutePath, strings.Join(SupportedManifests, ", "))
		}
	} else {
		if matchManifest(absolutePath) == nil {
			return Result{}, fmt.Errorf("unsupported manifest %s (supported: %s)", filepath.Base(absolutePath), strings.Join(SupportedManifests, ", "))
		}
		manifests = []string{absolutePath}
		root = filepath.Dir(absolutePath)
	}

	var dependencies []Dependency
	var targetFiles []string
	manifestProjectName := ""

	for _, manifest := range manifests {
		parser := matchManifest(manifest)
		name, manifestDependencies, err := parser.Parse(manifest)
		if err != nil {
			return Result{}, err
		}

		relativePath, relErr := filepath.Rel(root, manifest)
		if relErr != nil {
			relativePath = manifest
		}
		relativePath = filepath.ToSlash(relativePath)

		for i := range manifestDependencies {
			manifestDependencies[i].File = relativePath
		}

		dependencies = append(dependencies, manifestDependencies...)
		targetFiles = append(targetFiles, relativePath)
		if manifestProjectName == "" {
			manifestProjectName = strings.TrimSpace(name)
		}

		reportProgress(options.Progress, "Parsed %s (%s): %d dependencies", relativePath, parser.Ecosystem, len(manifestDependencies))
	}

	dependencies = dedupeDependencies(dependencies)
	sort.Slice(dependencies, func(i, j int) bool {
		if dependencies[i].Name == dependencies[j].Name {
			return dependencies[i].File < dependencies[j].File
		}
		return dependencies[i].Name < dependencies[j].Name
	})

	projectName := strings.TrimSpace(options.ProjectName)
	if projectName == "" {
		if info.IsDir() {
			projectName = filepath.Base(absolutePath)
		} else {
			projectName = manifestProjectName
		}
	}
	if projectName == "" || projectName == "." || projectName == string(filepath.Separator) {
		projectName = "unnamed-project"
	}

	source := options.Source
	if source == "" {
		source = root
	}

	client := NewGitHubClient(options.GitHubToken)
	reportProgress(options.Progress, "Checking %d dependencies against the GitHub Advisory Database...", len(dependencies))
	vulnerabilities, err := client.FindVulnerabilities(ctx, dependencies)
	if err != nil {
		return Result{}, fmt.Errorf("scan vulnerabilities: %w", err)
	}

	return Result{
		ProjectName:     projectName,
		Source:          source,
		TargetFile:      strings.Join(targetFiles, ", "),
		TargetFiles:     targetFiles,
		ScannerVersion:  ScannerVersion,
		Dependencies:    dependencies,
		Vulnerabilities: vulnerabilities,
	}, nil
}

func dedupeDependencies(values []Dependency) []Dependency {
	seen := make(map[string]bool, len(values))
	result := make([]Dependency, 0, len(values))
	for _, value := range values {
		key := strings.Join([]string{value.Ecosystem, strings.ToLower(value.Name), value.RequestedRange, value.Scope, value.File}, "|")
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, value)
	}

	return result
}

func reportProgress(progress func(string), format string, args ...any) {
	if progress == nil {
		return
	}
	progress(fmt.Sprintf(format, args...))
}
