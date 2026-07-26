package pkgscan

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	pathpkg "path"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	dockerclient "github.com/moby/moby/client"
)

// containerInventoryFiles are the exact file paths reconstructed from image
// layers: os-release plus the package database of every supported family.
var containerInventoryFiles = func() map[string]bool {
	files := map[string]bool{
		"etc/os-release":       true,
		"usr/lib/os-release":   true,
		"var/lib/dpkg/status":  true,
		"lib/apk/db/installed": true,
	}
	for _, path := range rpmDatabasePaths {
		files[path] = true
	}
	return files
}()

func isInventoryFile(layerPath string) bool {
	return containerInventoryFiles[layerPath] || isPacmanDescPath(layerPath)
}

func isPacmanDescPath(layerPath string) bool {
	return strings.HasPrefix(layerPath, "var/lib/pacman/local/") && strings.HasSuffix(layerPath, "/desc")
}

func RunContainer(ctx context.Context, options ContainerOptions) (Result, error) {
	imageName := strings.TrimSpace(options.Image)
	if imageName == "" {
		return Result{}, fmt.Errorf("image is required")
	}

	files, source, digest, err := loadContainerInventory(ctx, imageName, options.Local)
	if err != nil {
		return Result{}, err
	}

	osReleaseContent := files["etc/os-release"]
	if len(osReleaseContent) == 0 {
		osReleaseContent = files["usr/lib/os-release"]
	}
	if len(osReleaseContent) == 0 {
		return Result{}, fmt.Errorf("image does not contain os-release")
	}

	osRelease, err := parseOSRelease(bytes.NewReader(osReleaseContent))
	if err != nil {
		return Result{}, fmt.Errorf("parse image os-release: %w", err)
	}

	family, err := familyForOS(osRelease)
	if err != nil {
		return Result{}, err
	}

	packages, err := packagesFromImageFiles(files, family)
	if err != nil {
		return Result{}, err
	}
	reportProgress(options.Progress, "Found %d installed %s packages in %s.", len(packages), family, imageName)

	var vulnerabilities []Vulnerability
	if ecosystemForOS(osRelease) == "" {
		reportProgress(options.Progress, "OSV has no advisory feed for %s yet; sending the package inventory without CVE matching.", osDisplayName(osRelease))
	} else {
		vulnerabilities, err = findVulnerabilities(ctx, packages, osRelease, options.OSVBaseURL, options.Progress)
		if err != nil {
			return Result{}, fmt.Errorf("scan package vulnerabilities: %w", err)
		}
		reportProgress(options.Progress, "Found %d package vulnerabilities.", len(vulnerabilities))
	}

	return Result{
		Type:            "container",
		TargetName:      imageName,
		ImageName:       imageName,
		ImageRef:        imageName,
		ImageDigest:     digest,
		Source:          source,
		OSID:            osRelease.ID,
		OSName:          osDisplayName(osRelease),
		OSVersion:       osRelease.VersionID,
		OSCodename:      osRelease.VersionCodename,
		PackageManager:  string(family),
		ScannerVersion:  ScannerVersion,
		Packages:        packages,
		Vulnerabilities: vulnerabilities,
	}, nil
}

// packagesFromImageFiles parses the package database matching the image's
// distribution family from the files reconstructed out of the layers.
func packagesFromImageFiles(files map[string][]byte, family packageFamily) ([]Package, error) {
	switch family {
	case familyDpkg:
		content := files["var/lib/dpkg/status"]
		if len(content) == 0 {
			return nil, fmt.Errorf("image does not contain a dpkg status database")
		}
		return parseDpkgStatus(bytes.NewReader(content))
	case familyAPK:
		content := files["lib/apk/db/installed"]
		if len(content) == 0 {
			return nil, fmt.Errorf("image does not contain an apk database")
		}
		return parseApkInstalled(bytes.NewReader(content))
	case familyRPM:
		for _, path := range rpmDatabasePaths {
			if content := files[path]; len(content) > 0 {
				return parseRPMDatabase(content)
			}
		}
		return nil, fmt.Errorf("image does not contain an rpm database")
	case familyPacman:
		return packagesFromPacmanDescFiles(files)
	default:
		return nil, fmt.Errorf("unsupported package family: %s", family)
	}
}

func loadContainerInventory(ctx context.Context, imageName string, local bool) (map[string][]byte, string, string, error) {
	if local {
		files, digest, err := extractInventoryFilesFromDockerDaemon(ctx, imageName)
		return files, "docker-daemon:" + imageName, digest, err
	}

	ref, err := name.ParseReference(imageName, name.WeakValidation)
	if err != nil {
		return nil, "", "", fmt.Errorf("parse image reference: %w", err)
	}

	image, err := remote.Image(ref, remote.WithContext(ctx))
	if err != nil {
		return nil, "", "", fmt.Errorf("pull image from registry: %w (use --local to scan an image from the local Docker daemon)", err)
	}
	files, err := extractInventoryFiles(image)
	if err != nil {
		return nil, "", "", err
	}

	digest := ""
	if imageDigest, err := image.Digest(); err == nil {
		digest = imageDigest.String()
	}
	return files, ref.Name(), digest, nil
}

func extractInventoryFilesFromDockerDaemon(ctx context.Context, imageName string) (map[string][]byte, string, error) {
	client, err := dockerclient.New(dockerclient.FromEnv)
	if err != nil {
		return nil, "", fmt.Errorf("connect docker daemon: %w", err)
	}
	defer client.Close()

	inspect, err := client.ImageInspect(ctx, imageName)
	if err != nil {
		return nil, "", fmt.Errorf("inspect local docker image: %w", err)
	}

	reader, err := client.ImageSave(ctx, []string{imageName})
	if err != nil {
		return nil, "", fmt.Errorf("save local docker image stream: %w", err)
	}
	defer reader.Close()

	files, err := extractInventoryFilesFromDockerSave(reader, dockerLayerPaths(inspect.RootFS.Layers))
	if err != nil {
		return nil, "", err
	}

	digest := ""
	if len(inspect.RepoDigests) > 0 {
		digest = inspect.RepoDigests[0]
	} else {
		digest = inspect.ID
	}

	return files, digest, nil
}

func extractInventoryFiles(image v1.Image) (map[string][]byte, error) {
	layers, err := image.Layers()
	if err != nil {
		return nil, fmt.Errorf("read image layers: %w", err)
	}

	files := make(map[string][]byte)
	for _, layer := range layers {
		reader, err := layer.Uncompressed()
		if err != nil {
			return nil, fmt.Errorf("read image layer: %w", err)
		}

		if err := applyLayer(reader, files); err != nil {
			_ = reader.Close()
			return nil, err
		}
		if err := reader.Close(); err != nil {
			return nil, err
		}
	}

	return files, nil
}

func applyLayer(reader io.Reader, files map[string][]byte) error {
	tarReader := tar.NewReader(reader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read image layer tar: %w", err)
		}

		layerPath := cleanLayerPath(header.Name)
		if layerPath == "" {
			continue
		}
		if applyWhiteout(files, layerPath) {
			continue
		}
		if !isInventoryFile(layerPath) {
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			continue
		}

		content, err := io.ReadAll(tarReader)
		if err != nil {
			return fmt.Errorf("read %s from image layer: %w", layerPath, err)
		}
		files[layerPath] = content
	}
}

type dockerSaveManifestEntry struct {
	Layers []string `json:"Layers"`
}

type layerPatch struct {
	path string
	ops  []layerOp
}

type layerOp struct {
	kind    string
	path    string
	content []byte
}

const (
	layerOpPut          = "put"
	layerOpDelete       = "delete"
	layerOpDeletePrefix = "deletePrefix"
)

func dockerLayerPaths(layers []string) map[string]bool {
	paths := make(map[string]bool, len(layers))
	for _, layer := range layers {
		layer = strings.TrimPrefix(layer, "sha256:")
		if layer == "" {
			continue
		}
		paths["blobs/sha256/"+layer] = true
	}
	return paths
}

func extractInventoryFilesFromDockerSave(reader io.Reader, expectedLayerPaths map[string]bool) (map[string][]byte, error) {
	tarReader := tar.NewReader(reader)
	patchesByPath := make(map[string]layerPatch)
	var patchesInReadOrder []layerPatch
	var manifest []dockerSaveManifestEntry

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read docker image save tar: %w", err)
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			continue
		}

		entryPath := cleanLayerPath(header.Name)
		switch {
		case entryPath == "manifest.json":
			content, err := io.ReadAll(tarReader)
			if err != nil {
				return nil, fmt.Errorf("read docker image save manifest: %w", err)
			}
			if err := json.Unmarshal(content, &manifest); err != nil {
				return nil, fmt.Errorf("parse docker image save manifest: %w", err)
			}
		case isDockerSaveLayerEntry(entryPath, expectedLayerPaths):
			patch, err := readLayerPatch(entryPath, tarReader)
			if err != nil {
				return nil, err
			}
			patchesByPath[entryPath] = patch
			patchesInReadOrder = append(patchesInReadOrder, patch)
		}
	}

	files := make(map[string][]byte)
	applied := make(map[string]bool, len(patchesByPath))
	if len(manifest) > 0 {
		for _, layerPath := range manifest[0].Layers {
			layerPath = cleanLayerPath(layerPath)
			patch, ok := patchesByPath[layerPath]
			if !ok {
				continue
			}
			applyLayerPatch(files, patch)
			applied[layerPath] = true
		}
	}

	for _, patch := range patchesInReadOrder {
		if applied[patch.path] {
			continue
		}
		applyLayerPatch(files, patch)
	}

	return files, nil
}

func isDockerSaveLayerEntry(entryPath string, expectedLayerPaths map[string]bool) bool {
	return pathpkg.Base(entryPath) == "layer.tar" ||
		expectedLayerPaths[entryPath]
}

func readLayerPatch(layerPath string, reader io.Reader) (layerPatch, error) {
	tarReader := tar.NewReader(reader)
	patch := layerPatch{path: layerPath}

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return patch, nil
		}
		if err != nil {
			if len(patch.ops) == 0 && errors.Is(err, tar.ErrHeader) {
				return patch, nil
			}
			return layerPatch{}, fmt.Errorf("read docker image layer %s: %w", layerPath, err)
		}

		entryPath := cleanLayerPath(header.Name)
		if entryPath == "" {
			continue
		}
		if op, ok := whiteoutOp(entryPath); ok {
			patch.ops = append(patch.ops, op)
			continue
		}
		if !isInventoryFile(entryPath) {
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			continue
		}

		content, err := io.ReadAll(tarReader)
		if err != nil {
			return layerPatch{}, fmt.Errorf("read %s from docker image layer %s: %w", entryPath, layerPath, err)
		}
		patch.ops = append(patch.ops, layerOp{
			kind:    layerOpPut,
			path:    entryPath,
			content: content,
		})
	}
}

func applyLayerPatch(files map[string][]byte, patch layerPatch) {
	for _, op := range patch.ops {
		switch op.kind {
		case layerOpPut:
			files[op.path] = op.content
		case layerOpDelete:
			deletePath(files, op.path)
		case layerOpDeletePrefix:
			deletePrefix(files, op.path)
		}
	}
}

func cleanLayerPath(value string) string {
	clean := pathpkg.Clean(strings.TrimPrefix(value, "/"))
	if clean == "." {
		return ""
	}
	return clean
}

func applyWhiteout(files map[string][]byte, layerPath string) bool {
	op, ok := whiteoutOp(layerPath)
	if !ok {
		return false
	}
	switch op.kind {
	case layerOpDelete:
		deletePath(files, op.path)
	case layerOpDeletePrefix:
		deletePrefix(files, op.path)
	}
	return true
}

func whiteoutOp(layerPath string) (layerOp, bool) {
	dir, base := pathpkg.Split(layerPath)
	dir = strings.TrimSuffix(dir, "/")

	if base == ".wh..wh..opq" {
		prefix := ""
		if dir != "" {
			prefix = dir + "/"
		}
		return layerOp{kind: layerOpDeletePrefix, path: prefix}, true
	}

	if strings.HasPrefix(base, ".wh.") {
		return layerOp{
			kind: layerOpDelete,
			path: pathpkg.Join(dir, strings.TrimPrefix(base, ".wh.")),
		}, true
	}

	return layerOp{}, false
}

func deletePath(files map[string][]byte, target string) {
	for filePath := range files {
		if filePath == target || strings.HasPrefix(filePath, target+"/") {
			delete(files, filePath)
		}
	}
}

func deletePrefix(files map[string][]byte, prefix string) {
	for filePath := range files {
		if prefix == "" || strings.HasPrefix(filePath, prefix) {
			delete(files, filePath)
		}
	}
}
