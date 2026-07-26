package sca

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverManifests(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name":"web"}`)
	writeFile(t, filepath.Join(root, "api", "go.mod"), "module example.com/api\n")
	writeFile(t, filepath.Join(root, "worker", "requirements.txt"), "requests==2.31.0\n")
	writeFile(t, filepath.Join(root, "node_modules", "dep", "package.json"), `{"name":"dep"}`)
	writeFile(t, filepath.Join(root, "README.md"), "readme")

	manifests, err := discoverManifests(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifests) != 3 {
		t.Fatalf("expected 3 manifests, got %d: %v", len(manifests), manifests)
	}
}

func TestReadRequirementsTxt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requirements.txt")
	writeFile(t, path, "# comment\nrequests==2.31.0\nflask>=2.0\nDjango[argon2]==4.2.7 ; python_version > \"3.8\"\n-r other.txt\n")

	_, dependencies, err := readRequirementsTxt(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(dependencies) != 3 {
		t.Fatalf("expected 3 dependencies, got %d: %v", len(dependencies), dependencies)
	}
	if dependencies[0].Name != "requests" || dependencies[0].ResolvedVersion != "2.31.0" {
		t.Fatalf("unexpected first dependency: %+v", dependencies[0])
	}
	if dependencies[1].ResolvedVersion != "" {
		t.Fatalf("range requirement should not resolve a version: %+v", dependencies[1])
	}
	if dependencies[2].Name != "django" || dependencies[2].ResolvedVersion != "4.2.7" {
		t.Fatalf("unexpected django dependency: %+v", dependencies[2])
	}
}

func TestReadGoMod(t *testing.T) {
	path := filepath.Join(t.TempDir(), "go.mod")
	writeFile(t, path, `module example.com/service

go 1.22

require (
	github.com/gin-gonic/gin v1.9.1
	golang.org/x/crypto v0.17.0 // indirect
)

require github.com/stretchr/testify v1.8.4
`)

	projectName, dependencies, err := readGoMod(path)
	if err != nil {
		t.Fatal(err)
	}
	if projectName != "service" {
		t.Fatalf("unexpected project name: %s", projectName)
	}
	if len(dependencies) != 3 {
		t.Fatalf("expected 3 dependencies, got %d: %v", len(dependencies), dependencies)
	}
	if dependencies[0].ResolvedVersion != "1.9.1" {
		t.Fatalf("unexpected version: %+v", dependencies[0])
	}
	if dependencies[1].Scope != "indirect" {
		t.Fatalf("expected indirect scope: %+v", dependencies[1])
	}
}

func TestReadPomXML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pom.xml")
	writeFile(t, path, `<?xml version="1.0"?>
<project>
  <artifactId>payments</artifactId>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.15.2</version>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>interpolated</artifactId>
      <version>${example.version}</version>
    </dependency>
  </dependencies>
</project>
`)

	projectName, dependencies, err := readPomXML(path)
	if err != nil {
		t.Fatal(err)
	}
	if projectName != "payments" {
		t.Fatalf("unexpected project name: %s", projectName)
	}
	if len(dependencies) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(dependencies))
	}
	if dependencies[0].Name != "com.fasterxml.jackson.core:jackson-databind" || dependencies[0].ResolvedVersion != "2.15.2" {
		t.Fatalf("unexpected dependency: %+v", dependencies[0])
	}
	if dependencies[1].ResolvedVersion != "" {
		t.Fatalf("interpolated version should not resolve: %+v", dependencies[1])
	}
}

func TestReadGemfileLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Gemfile.lock")
	writeFile(t, path, `GEM
  remote: https://rubygems.org/
  specs:
    rails (7.1.3.4)
      actioncable (= 7.1.3.4)
    rack (3.0.8)

PLATFORMS
  ruby
`)

	_, dependencies, err := readGemfileLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(dependencies) != 2 {
		t.Fatalf("expected 2 dependencies, got %d: %v", len(dependencies), dependencies)
	}
	if dependencies[0].Name != "rails" || dependencies[0].ResolvedVersion != "7.1.3.4" {
		t.Fatalf("unexpected dependency: %+v", dependencies[0])
	}
}

func TestReadCargoToml(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Cargo.toml")
	writeFile(t, path, `[package]
name = "runtz-agent"
version = "0.1.0"

[dependencies]
serde = { version = "1.0.195", features = ["derive"] }
tokio = "1.35.1"
local-crate = { path = "../local" }

[dev-dependencies]
insta = "1.34.0"
`)

	projectName, dependencies, err := readCargoToml(path)
	if err != nil {
		t.Fatal(err)
	}
	if projectName != "runtz-agent" {
		t.Fatalf("unexpected project name: %s", projectName)
	}
	if len(dependencies) != 3 {
		t.Fatalf("expected 3 dependencies, got %d: %v", len(dependencies), dependencies)
	}
	if dependencies[0].Name != "serde" || dependencies[0].ResolvedVersion != "1.0.195" {
		t.Fatalf("unexpected dependency: %+v", dependencies[0])
	}
	if dependencies[2].Scope != "dev-dependencies" {
		t.Fatalf("unexpected scope: %+v", dependencies[2])
	}
}

func TestReadCsproj(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Api.csproj")
	writeFile(t, path, `<Project Sdk="Microsoft.NET.Sdk.Web">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Serilog">
      <Version>3.1.1</Version>
    </PackageReference>
  </ItemGroup>
</Project>
`)

	projectName, dependencies, err := readCsproj(path)
	if err != nil {
		t.Fatal(err)
	}
	if projectName != "Api" {
		t.Fatalf("unexpected project name: %s", projectName)
	}
	if len(dependencies) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(dependencies))
	}
	if dependencies[0].Name != "Newtonsoft.Json" || dependencies[0].ResolvedVersion != "13.0.3" {
		t.Fatalf("unexpected dependency: %+v", dependencies[0])
	}
	if dependencies[1].ResolvedVersion != "3.1.1" {
		t.Fatalf("element version should resolve: %+v", dependencies[1])
	}
}

func TestReadComposerJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "composer.json")
	writeFile(t, path, `{
  "name": "acme/shop",
  "require": {
    "php": ">=8.1",
    "laravel/framework": "10.43.0"
  },
  "require-dev": {
    "phpunit/phpunit": "^10.5"
  }
}`)

	projectName, dependencies, err := readComposerJSON(path)
	if err != nil {
		t.Fatal(err)
	}
	if projectName != "acme/shop" {
		t.Fatalf("unexpected project name: %s", projectName)
	}
	if len(dependencies) != 2 {
		t.Fatalf("php platform requirement should be skipped, got %d: %v", len(dependencies), dependencies)
	}
}

func TestMatchManifest(t *testing.T) {
	cases := map[string]string{
		"package.json":     "npm",
		"requirements.txt": "pip",
		"go.mod":           "go",
		"pom.xml":          "maven",
		"Gemfile.lock":     "rubygems",
		"composer.json":    "composer",
		"Cargo.toml":       "rust",
		"Api.csproj":       "nuget",
	}
	for file, ecosystem := range cases {
		parser := matchManifest(file)
		if parser == nil {
			t.Fatalf("expected %s to match", file)
		}
		if parser.Ecosystem != ecosystem {
			t.Fatalf("expected %s for %s, got %s", ecosystem, file, parser.Ecosystem)
		}
	}
	if matchManifest("main.go") != nil {
		t.Fatal("main.go should not match a manifest")
	}
}
