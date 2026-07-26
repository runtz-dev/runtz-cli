package sast

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/runtz-dev/runtz-cli/internal/report"
	"github.com/runtz-dev/runtz-cli/internal/version"
)

var ScannerVersion = version.Scanner()

type Options struct {
	Path        string
	ProjectName string
	Source      string
	Progress    func(string)
}

type rule struct {
	id          string
	title       string
	description string
	severity    string
	category    string
	pattern     *regexp.Regexp
	remediation string
	filter      func(string) bool
}

var rules = []rule{
	{
		id:          "SAST001",
		title:       "Possible private key committed",
		description: "The file contains a private key marker.",
		severity:    "critical",
		category:    "secret",
		pattern:     regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |OPENSSH |)?PRIVATE KEY-----`),
		remediation: "Remove the key from source control, rotate it, and load it from a secret manager.",
	},
	{
		id:          "SAST002",
		title:       "Possible AWS access key",
		description: "The line contains a value shaped like an AWS access key id.",
		severity:    "high",
		category:    "secret",
		pattern:     regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`),
		remediation: "Rotate the key and use the runtime secret mechanism instead of committing credentials.",
	},
	{
		id:          "SAST003",
		title:       "Possible hardcoded secret",
		description: "A credential-like variable is assigned a long literal value.",
		severity:    "high",
		category:    "secret",
		pattern:     regexp.MustCompile(`(?i)\b(api[_-]?key|secret|token|password|passwd|pwd)\b\s*[:=]\s*['"][^'"\s]{16,}['"]`),
		remediation: "Move secrets to environment variables or a secret manager and rotate exposed values.",
		filter: func(line string) bool {
			lower := strings.ToLower(line)
			ignored := []string{"example", "placeholder", "changeme", "change-me", "dummy", "sample", "process.env", "os.getenv", "getenv"}
			for _, value := range ignored {
				if strings.Contains(lower, value) {
					return false
				}
			}
			return true
		},
	},
	{
		id:          "SAST004",
		title:       "Dynamic code execution",
		description: "The code calls eval, which can execute attacker-controlled input.",
		severity:    "high",
		category:    "injection",
		pattern:     regexp.MustCompile(`\beval\s*\(`),
		remediation: "Replace eval with a parser or an explicit dispatch table for expected values.",
	},
	{
		id:          "SAST005",
		title:       "Shell execution enabled",
		description: "The code enables shell execution for a child process.",
		severity:    "high",
		category:    "command-injection",
		pattern:     regexp.MustCompile(`\bshell\s*=\s*True\b|child_process\.(exec|execSync)\s*\(`),
		remediation: "Avoid shell mode and pass arguments as an array to a safe process execution API.",
	},
	{
		id:          "SAST006",
		title:       "TLS verification disabled",
		description: "The code disables certificate verification.",
		severity:    "high",
		category:    "transport-security",
		pattern:     regexp.MustCompile(`InsecureSkipVerify\s*:\s*true|verify\s*=\s*False`),
		remediation: "Keep TLS certificate verification enabled and configure trusted roots when needed.",
	},
	{
		id:          "SAST007",
		title:       "Weak hash function",
		description: "The code uses MD5 or SHA-1, which are not suitable for security-sensitive hashing.",
		severity:    "low",
		category:    "cryptography",
		pattern:     regexp.MustCompile(`\b(md5|sha1)\.(New|createHash)\s*\(|createHash\s*\(\s*['"](md5|sha1)['"]`),
		remediation: "Use SHA-256 or a purpose-built password hashing function such as bcrypt or Argon2.",
	},
}

// supportedExtensions covers the languages the SAST scan supports:
// JavaScript/TypeScript, Python, Go, Java/Kotlin, Ruby, PHP, Rust and C#/.NET.
var supportedExtensions = map[string]bool{
	".cs":   true,
	".go":   true,
	".java": true,
	".js":   true,
	".jsx":  true,
	".kt":   true,
	".kts":  true,
	".mjs":  true,
	".cjs":  true,
	".php":  true,
	".py":   true,
	".rb":   true,
	".rs":   true,
	".ts":   true,
	".tsx":  true,
}

var ignoredDirectories = map[string]bool{
	".cache":       true,
	".git":         true,
	".next":        true,
	".terraform":   true,
	".venv":        true,
	"build":        true,
	"coverage":     true,
	"dist":         true,
	"node_modules": true,
	"target":       true,
	"vendor":       true,
	"venv":         true,
}

func Run(ctx context.Context, options Options) (report.Result, error) {
	targetPath := strings.TrimSpace(options.Path)
	if targetPath == "" {
		targetPath = "."
	}

	absolutePath, err := filepath.Abs(targetPath)
	if err != nil {
		return report.Result{}, fmt.Errorf("resolve scan path: %w", err)
	}

	info, err := os.Stat(absolutePath)
	if err != nil {
		return report.Result{}, fmt.Errorf("read scan path: %w", err)
	}

	source := strings.TrimSpace(options.Source)
	if source == "" {
		source = absolutePath
	}

	projectName := strings.TrimSpace(options.ProjectName)
	if projectName == "" {
		if info.IsDir() {
			projectName = filepath.Base(absolutePath)
		} else {
			projectName = filepath.Base(filepath.Dir(absolutePath))
		}
	}
	if projectName == "" || projectName == "." || projectName == string(filepath.Separator) {
		projectName = "source"
	}

	var findings []report.Finding
	filesScanned := 0

	err = filepath.WalkDir(absolutePath, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}

		if entry.IsDir() {
			if path != absolutePath && ignoredDirectories[entry.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		if !supportedExtensions[strings.ToLower(filepath.Ext(path))] {
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > 1024*1024 {
			return nil
		}

		fileFindings, err := scanFile(path, absolutePath)
		if err != nil {
			return err
		}
		filesScanned++
		findings = append(findings, fileFindings...)
		return nil
	})
	if err != nil {
		return report.Result{}, fmt.Errorf("scan source files: %w", err)
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File == findings[j].File {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].File < findings[j].File
	})

	reportProgress(options.Progress, "Scanned %d source files and found %d SAST findings.", filesScanned, len(findings))

	return report.Result{
		Type:           "sast",
		ProjectName:    projectName,
		TargetName:     projectName,
		Source:         source,
		ScannerVersion: ScannerVersion,
		FilesScanned:   filesScanned,
		Findings:       findings,
	}, nil
}

func scanFile(path, root string) ([]report.Finding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	relativePath, err := filepath.Rel(root, path)
	if err != nil {
		relativePath = path
	}
	if relativePath == "." {
		relativePath = filepath.Base(path)
	}
	relativePath = filepath.ToSlash(relativePath)

	var findings []report.Finding
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		for _, rule := range rules {
			if rule.filter != nil && !rule.filter(line) {
				continue
			}
			location := rule.pattern.FindStringIndex(line)
			if location == nil {
				continue
			}
			findings = append(findings, report.Finding{
				ID:          rule.id,
				Title:       rule.title,
				Description: rule.description,
				Severity:    rule.severity,
				Category:    rule.category,
				File:        relativePath,
				Line:        lineNumber,
				Column:      location[0] + 1,
				Remediation: rule.remediation,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}

	return findings, nil
}

func reportProgress(progress func(string), format string, args ...any) {
	if progress == nil {
		return
	}
	progress(fmt.Sprintf(format, args...))
}
