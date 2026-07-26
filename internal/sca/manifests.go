package sca

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// manifestParser describes one supported SCA ecosystem: the language shown to
// the user, the GitHub Advisory Database ecosystem identifier and the parser
// for its dependency manifest.
type manifestParser struct {
	Language  string
	Ecosystem string
	Parse     func(path string) (string, []Dependency, error)
}

var manifestParsers = []struct {
	Match func(base string) bool
	manifestParser
}{
	{
		Match: matchName("package.json"),
		manifestParser: manifestParser{
			Language:  "JavaScript/TypeScript",
			Ecosystem: "npm",
			Parse:     ReadPackageJSON,
		},
	},
	{
		Match: matchName("requirements.txt"),
		manifestParser: manifestParser{
			Language:  "Python",
			Ecosystem: "pip",
			Parse:     readRequirementsTxt,
		},
	},
	{
		Match: matchName("go.mod"),
		manifestParser: manifestParser{
			Language:  "Go",
			Ecosystem: "go",
			Parse:     readGoMod,
		},
	},
	{
		Match: matchName("pom.xml"),
		manifestParser: manifestParser{
			Language:  "Java/Kotlin",
			Ecosystem: "maven",
			Parse:     readPomXML,
		},
	},
	{
		Match: matchName("gemfile.lock"),
		manifestParser: manifestParser{
			Language:  "Ruby",
			Ecosystem: "rubygems",
			Parse:     readGemfileLock,
		},
	},
	{
		Match: matchName("composer.json"),
		manifestParser: manifestParser{
			Language:  "PHP",
			Ecosystem: "composer",
			Parse:     readComposerJSON,
		},
	},
	{
		Match: matchName("cargo.toml"),
		manifestParser: manifestParser{
			Language:  "Rust",
			Ecosystem: "rust",
			Parse:     readCargoToml,
		},
	},
	{
		Match: func(base string) bool { return strings.HasSuffix(base, ".csproj") },
		manifestParser: manifestParser{
			Language:  "C#/.NET",
			Ecosystem: "nuget",
			Parse:     readCsproj,
		},
	},
}

// SupportedManifests lists the manifest file names shown in errors and help.
var SupportedManifests = []string{
	"package.json",
	"requirements.txt",
	"go.mod",
	"pom.xml",
	"Gemfile.lock",
	"composer.json",
	"Cargo.toml",
	"*.csproj",
}

var ignoredDirectories = map[string]bool{
	".cache":       true,
	".git":         true,
	".next":        true,
	".terraform":   true,
	".venv":        true,
	"bin":          true,
	"build":        true,
	"coverage":     true,
	"dist":         true,
	"node_modules": true,
	"obj":          true,
	"target":       true,
	"testdata":     true,
	"vendor":       true,
	"venv":         true,
}

func matchName(name string) func(string) bool {
	return func(base string) bool { return base == name }
}

func matchManifest(path string) *manifestParser {
	base := strings.ToLower(filepath.Base(path))
	for i := range manifestParsers {
		if manifestParsers[i].Match(base) {
			return &manifestParsers[i].manifestParser
		}
	}
	return nil
}

// discoverManifests walks a repository root and returns every supported
// dependency manifest, skipping dependency and build output directories.
func discoverManifests(root string) ([]string, error) {
	var manifests []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && ignoredDirectories[entry.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if matchManifest(path) != nil {
			manifests = append(manifests, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("discover manifests: %w", err)
	}

	sort.Strings(manifests)
	return manifests, nil
}
