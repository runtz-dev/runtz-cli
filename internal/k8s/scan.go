package k8s

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/runtz-dev/runtz-cli/internal/report"
	"github.com/runtz-dev/runtz-cli/internal/version"
	"gopkg.in/yaml.v3"
)

var ScannerVersion = version.Scanner()

type Options struct {
	Path          string
	Target        string
	Source        string
	Kubectl       string
	Kubeconfig    string
	Context       string
	Namespace     string
	AllNamespaces bool
	Progress      func(string)
}

var ignoredDirectories = map[string]bool{
	".git":         true,
	".helm":        true,
	".terraform":   true,
	"charts":       false,
	"node_modules": true,
	"vendor":       true,
}

func Run(ctx context.Context, options Options) (report.Result, error) {
	targetPath := strings.TrimSpace(options.Path)
	if targetPath != "" {
		return runManifestScan(ctx, options, targetPath)
	}

	return runClusterScan(ctx, options)
}

func runManifestScan(ctx context.Context, options Options, targetPath string) (report.Result, error) {
	absolutePath, err := filepath.Abs(targetPath)
	if err != nil {
		return report.Result{}, fmt.Errorf("resolve manifest path: %w", err)
	}
	info, err := os.Stat(absolutePath)
	if err != nil {
		return report.Result{}, fmt.Errorf("read manifest path: %w", err)
	}

	source := strings.TrimSpace(options.Source)
	if source == "" {
		source = absolutePath
	}

	targetName := strings.TrimSpace(options.Target)
	if targetName == "" {
		if info.IsDir() {
			targetName = filepath.Base(absolutePath)
		} else {
			targetName = filepath.Base(filepath.Dir(absolutePath))
		}
	}
	if targetName == "" || targetName == "." || targetName == string(filepath.Separator) {
		targetName = "kubernetes-manifests"
	}

	var findings []report.Finding
	filesScanned := 0
	resourcesScanned := 0

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
		if !isManifestFile(path) {
			return nil
		}

		fileFindings, resources, err := scanManifestFile(path, absolutePath)
		if err != nil {
			return err
		}
		filesScanned++
		resourcesScanned += resources
		findings = append(findings, fileFindings...)
		return nil
	})
	if err != nil {
		return report.Result{}, fmt.Errorf("scan kubernetes manifests: %w", err)
	}

	sortFindings(findings)

	reportProgress(options.Progress, "Scanned %d manifest files and %d Kubernetes resources; found %d findings.", filesScanned, resourcesScanned, len(findings))

	return report.Result{
		Type:             "k8s",
		ProjectName:      targetName,
		TargetName:       targetName,
		Source:           source,
		ScannerVersion:   ScannerVersion,
		FilesScanned:     filesScanned,
		ResourcesScanned: resourcesScanned,
		Findings:         findings,
	}, nil
}

func runClusterScan(ctx context.Context, options Options) (report.Result, error) {
	kubectl := strings.TrimSpace(options.Kubectl)
	if kubectl == "" {
		kubectl = "kubectl"
	}

	currentContext := strings.TrimSpace(options.Context)
	if currentContext == "" {
		if output, err := kubectlOutput(ctx, kubectl, kubectlBaseArgs(options, "config", "current-context")); err == nil {
			currentContext = strings.TrimSpace(string(output))
		}
	}

	targetName := strings.TrimSpace(options.Target)
	if targetName == "" {
		targetName = currentContext
	}
	if targetName == "" {
		targetName = "kubernetes-cluster"
	}

	source := strings.TrimSpace(options.Source)
	if source == "" {
		source = "kubectl"
		if currentContext != "" {
			source += ":" + currentContext
		}
		if strings.TrimSpace(options.Namespace) != "" {
			source += "/namespace/" + strings.TrimSpace(options.Namespace)
		} else if options.AllNamespaces {
			source += "/all-namespaces"
		}
	}

	namespacedResources := []string{
		"pods",
		"deployments",
		"daemonsets",
		"statefulsets",
		"jobs",
		"cronjobs",
		"services",
		"ingress",
		"roles",
		"rolebindings",
	}
	clusterResources := []string{"clusterroles", "clusterrolebindings"}

	var findings []report.Finding
	resourcesScanned := 0
	successfulGets := 0
	var firstErr error

	for _, resource := range namespacedResources {
		content, err := kubectlGetResource(ctx, kubectl, options, resource, true)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			findings = append(findings, kubectlReadFinding(resource, err))
			continue
		}
		successfulGets++
		resourceFindings, count, err := scanYAMLContent(content, "kubectl:get/"+resource)
		if err != nil {
			return report.Result{}, err
		}
		resourcesScanned += count
		findings = append(findings, resourceFindings...)
	}

	for _, resource := range clusterResources {
		content, err := kubectlGetResource(ctx, kubectl, options, resource, false)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			findings = append(findings, kubectlReadFinding(resource, err))
			continue
		}
		successfulGets++
		resourceFindings, count, err := scanYAMLContent(content, "kubectl:get/"+resource)
		if err != nil {
			return report.Result{}, err
		}
		resourcesScanned += count
		findings = append(findings, resourceFindings...)
	}

	if successfulGets == 0 && firstErr != nil {
		return report.Result{}, fmt.Errorf("kubectl scan failed: %w", firstErr)
	}

	sortFindings(findings)
	reportProgress(options.Progress, "Scanned %d Kubernetes resources from kubectl; found %d findings.", resourcesScanned, len(findings))

	return report.Result{
		Type:             "k8s",
		ProjectName:      targetName,
		TargetName:       targetName,
		Source:           source,
		ScannerVersion:   ScannerVersion,
		ResourcesScanned: resourcesScanned,
		Findings:         findings,
	}, nil
}

func scanManifestFile(path, root string) ([]report.Finding, int, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, fmt.Errorf("read manifest %s: %w", path, err)
	}

	relativePath, err := filepath.Rel(root, path)
	if err != nil {
		relativePath = path
	}
	if relativePath == "." {
		relativePath = filepath.Base(path)
	}
	relativePath = filepath.ToSlash(relativePath)

	return scanYAMLContent(content, relativePath)
}

func scanYAMLContent(content []byte, source string) ([]report.Finding, int, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	var findings []report.Finding
	resources := 0

	for {
		var document map[string]any
		if err := decoder.Decode(&document); err != nil {
			if err == io.EOF {
				break
			}
			return nil, 0, fmt.Errorf("parse manifest %s: %w", source, err)
		}
		if len(document) == 0 {
			continue
		}
		documentFindings, count := scanDocument(document, source)
		resources += count
		findings = append(findings, documentFindings...)
	}

	return findings, resources, nil
}

func scanDocument(document map[string]any, source string) ([]report.Finding, int) {
	if strings.EqualFold(stringValue(document, "kind"), "List") {
		var findings []report.Finding
		resources := 0
		for _, item := range sliceValue(document["items"]) {
			itemFindings, count := scanDocument(asMap(item), source)
			resources += count
			findings = append(findings, itemFindings...)
		}
		return findings, resources
	}

	kind := stringValue(document, "kind")
	name, namespace := metadata(document)
	if kind == "" || name == "" {
		return nil, 0
	}

	return scanResource(document, source, kind, name, namespace), 1
}

func scanResource(resource map[string]any, file, kind, name, namespace string) []report.Finding {
	var findings []report.Finding

	switch strings.ToLower(kind) {
	case "pod", "deployment", "replicaset", "daemonset", "statefulset", "job", "cronjob":
		podSpec, ok := podSpecFor(resource, kind)
		if !ok {
			return findings
		}
		findings = append(findings, scanPodSpec(podSpec, file, kind, name, namespace)...)
	case "service":
		serviceType := strings.ToLower(stringValue(nestedMap(resource, "spec"), "type"))
		if serviceType == "loadbalancer" || serviceType == "nodeport" {
			findings = append(findings, finding("K8S010", "Public service exposure", "medium", "network", file, kind, name, namespace, "Service type "+serviceType+" can expose workloads outside the cluster.", "Use ClusterIP by default and expose services through controlled ingress when possible."))
		}
	case "ingress":
		spec := nestedMap(resource, "spec")
		if len(sliceValue(spec["tls"])) == 0 {
			findings = append(findings, finding("K8S011", "Ingress without TLS", "medium", "network", file, kind, name, namespace, "Ingress has no TLS block configured.", "Configure TLS for ingress hosts and redirect HTTP traffic to HTTPS."))
		}
	case "clusterrolebinding", "rolebinding":
		roleRef := nestedMap(resource, "roleRef")
		if strings.EqualFold(stringValue(roleRef, "kind"), "ClusterRole") && stringValue(roleRef, "name") == "cluster-admin" {
			findings = append(findings, finding("K8S012", "cluster-admin binding", "critical", "rbac", file, kind, name, namespace, "Binding grants cluster-admin privileges.", "Bind the narrowest role required by the subject instead of cluster-admin."))
		}
	case "clusterrole", "role":
		for _, rule := range sliceValue(resource["rules"]) {
			ruleMap := asMap(rule)
			if containsString(sliceValue(ruleMap["verbs"]), "*") || containsString(sliceValue(ruleMap["resources"]), "*") {
				findings = append(findings, finding("K8S013", "Wildcard RBAC rule", "high", "rbac", file, kind, name, namespace, "Role grants wildcard verbs or resources.", "Replace wildcards with explicit verbs and resource names."))
				break
			}
		}
	}

	return findings
}

func scanPodSpec(podSpec map[string]any, file, kind, name, namespace string) []report.Finding {
	var findings []report.Finding

	if value, ok := boolValue(podSpec["hostNetwork"]); ok && value {
		findings = append(findings, finding("K8S001", "hostNetwork enabled", "high", "pod-security", file, kind, name, namespace, "Workload uses the node network namespace.", "Disable hostNetwork unless the workload explicitly requires node networking."))
	}
	if value, ok := boolValue(podSpec["hostPID"]); ok && value {
		findings = append(findings, finding("K8S002", "hostPID enabled", "high", "pod-security", file, kind, name, namespace, "Workload can access host process IDs.", "Disable hostPID for regular application workloads."))
	}
	if value, ok := boolValue(podSpec["hostIPC"]); ok && value {
		findings = append(findings, finding("K8S003", "hostIPC enabled", "high", "pod-security", file, kind, name, namespace, "Workload can access host IPC namespace.", "Disable hostIPC for regular application workloads."))
	}
	if serviceAccount := strings.TrimSpace(stringValue(podSpec, "serviceAccountName")); serviceAccount == "" || serviceAccount == "default" {
		findings = append(findings, finding("K8S018", "Default service account", "low", "rbac", file, kind, name, namespace, "Workload uses the default service account.", "Create a dedicated service account with only the permissions required by this workload."))
	}
	if value, ok := boolValue(podSpec["automountServiceAccountToken"]); !ok || value {
		findings = append(findings, finding("K8S019", "Service account token automounted", "medium", "rbac", file, kind, name, namespace, "Workload can automatically mount a service account token.", "Set automountServiceAccountToken: false unless the workload needs to call the Kubernetes API."))
	}

	for _, volume := range sliceValue(podSpec["volumes"]) {
		volumeMap := asMap(volume)
		hostPath := nestedMap(volumeMap, "hostPath")
		if len(hostPath) == 0 {
			continue
		}
		hostPathValue := stringValue(hostPath, "path")
		severity := "high"
		if hostPathValue == "/var/run/docker.sock" || hostPathValue == "/run/containerd/containerd.sock" {
			severity = "critical"
		}
		findings = append(findings, finding("K8S004", "hostPath volume mounted", severity, "pod-security", file, kind, name, namespace, "Workload mounts host path "+hostPathValue+".", "Avoid hostPath volumes or constrain them with strict admission policies."))
	}

	podSecurityContext := nestedMap(podSpec, "securityContext")
	findings = append(findings, scanContainers(sliceValue(podSpec["initContainers"]), podSecurityContext, true, file, kind, name, namespace)...)
	findings = append(findings, scanContainers(sliceValue(podSpec["containers"]), podSecurityContext, false, file, kind, name, namespace)...)

	return findings
}

func scanContainers(containers []any, podSecurityContext map[string]any, init bool, file, kind, resourceName, namespace string) []report.Finding {
	var findings []report.Finding

	for _, rawContainer := range containers {
		container := asMap(rawContainer)
		containerName := stringValue(container, "name")
		if containerName == "" {
			containerName = "unnamed-container"
		}
		if init {
			containerName = "init:" + containerName
		}
		resourceLabel := resourceName + "/" + containerName
		securityContext := nestedMap(container, "securityContext")

		if value, ok := boolValue(securityContext["privileged"]); ok && value {
			findings = append(findings, finding("K8S005", "Privileged container", "critical", "container-security", file, kind, resourceLabel, namespace, "Container runs in privileged mode.", "Remove privileged mode and grant only the exact capabilities required."))
		}
		if value, ok := boolValue(securityContext["allowPrivilegeEscalation"]); !ok || value {
			findings = append(findings, finding("K8S006", "Privilege escalation not disabled", "medium", "container-security", file, kind, resourceLabel, namespace, "Container does not set allowPrivilegeEscalation to false.", "Set securityContext.allowPrivilegeEscalation: false."))
		}
		if !runsAsNonRoot(securityContext, podSecurityContext) {
			findings = append(findings, finding("K8S007", "Container may run as root", "medium", "container-security", file, kind, resourceLabel, namespace, "Container does not require a non-root user.", "Set runAsNonRoot: true and provide a non-zero runAsUser."))
		}
		if value, ok := boolValue(securityContext["readOnlyRootFilesystem"]); !ok || !value {
			findings = append(findings, finding("K8S008", "Writable root filesystem", "low", "container-security", file, kind, resourceLabel, namespace, "Container root filesystem is writable.", "Set readOnlyRootFilesystem: true and mount writable volumes only where needed."))
		}

		addedCapabilities := sliceValue(nestedMap(securityContext, "capabilities")["add"])
		if containsString(addedCapabilities, "ALL") || containsString(addedCapabilities, "SYS_ADMIN") || containsString(addedCapabilities, "NET_ADMIN") {
			findings = append(findings, finding("K8S014", "Dangerous Linux capability", "high", "container-security", file, kind, resourceLabel, namespace, "Container adds broad Linux capabilities.", "Drop all capabilities by default and add only narrowly required capabilities."))
		}

		image := stringValue(container, "image")
		if image == "" || imageUsesLatest(image) {
			findings = append(findings, finding("K8S009", "Mutable image tag", "medium", "supply-chain", file, kind, resourceLabel, namespace, "Container image uses no tag or the latest tag.", "Pin images to an immutable tag or digest."))
		}

		resources := nestedMap(container, "resources")
		if len(nestedMap(resources, "requests")) == 0 || len(nestedMap(resources, "limits")) == 0 {
			findings = append(findings, finding("K8S015", "Missing resource requests or limits", "medium", "resilience", file, kind, resourceLabel, namespace, "Container does not define both resource requests and limits.", "Set CPU and memory requests and limits for predictable scheduling and blast-radius control."))
		}
		if len(nestedMap(container, "readinessProbe")) == 0 && !init {
			findings = append(findings, finding("K8S016", "Missing readiness probe", "low", "resilience", file, kind, resourceLabel, namespace, "Container has no readiness probe.", "Add a readiness probe for application workloads that receive traffic."))
		}
		if len(nestedMap(container, "livenessProbe")) == 0 && !init {
			findings = append(findings, finding("K8S017", "Missing liveness probe", "low", "resilience", file, kind, resourceLabel, namespace, "Container has no liveness probe.", "Add a liveness probe when the app can enter an unrecoverable unhealthy state."))
		}
	}

	return findings
}

func podSpecFor(resource map[string]any, kind string) (map[string]any, bool) {
	spec := nestedMap(resource, "spec")
	switch strings.ToLower(kind) {
	case "pod":
		return spec, len(spec) > 0
	case "cronjob":
		podSpec := nestedMap(resource, "spec", "jobTemplate", "spec", "template", "spec")
		return podSpec, len(podSpec) > 0
	default:
		podSpec := nestedMap(spec, "template", "spec")
		return podSpec, len(podSpec) > 0
	}
}

func finding(id, title, severity, category, file, kind, name, namespace, description, remediation string) report.Finding {
	return report.Finding{
		ID:           id,
		Title:        title,
		Description:  description,
		Severity:     severity,
		Category:     category,
		File:         file,
		ResourceKind: kind,
		ResourceName: name,
		Namespace:    namespace,
		Remediation:  remediation,
	}
}

func metadata(resource map[string]any) (string, string) {
	metadata := nestedMap(resource, "metadata")
	return stringValue(metadata, "name"), stringValue(metadata, "namespace")
}

func nestedMap(root map[string]any, keys ...string) map[string]any {
	current := root
	for _, key := range keys {
		value, ok := current[key]
		if !ok {
			return map[string]any{}
		}
		current = asMap(value)
		if len(current) == 0 {
			return map[string]any{}
		}
	}
	return current
}

func asMap(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return typed
	case map[any]any:
		result := make(map[string]any, len(typed))
		for key, value := range typed {
			result[fmt.Sprint(key)] = value
		}
		return result
	default:
		return map[string]any{}
	}
}

func sliceValue(value any) []any {
	switch typed := value.(type) {
	case []any:
		return typed
	default:
		return nil
	}
}

func stringValue(root map[string]any, key string) string {
	switch value := root[key].(type) {
	case string:
		return strings.TrimSpace(value)
	default:
		return ""
	}
}

func boolValue(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	default:
		return false, false
	}
}

func containsString(values []any, expected string) bool {
	for _, rawValue := range values {
		if strings.EqualFold(fmt.Sprint(rawValue), expected) {
			return true
		}
	}
	return false
}

func runsAsNonRoot(containerSecurityContext, podSecurityContext map[string]any) bool {
	if value, ok := boolValue(containerSecurityContext["runAsNonRoot"]); ok {
		return value
	}
	if value, ok := boolValue(podSecurityContext["runAsNonRoot"]); ok {
		return value
	}
	return false
}

func imageUsesLatest(image string) bool {
	image = strings.TrimSpace(image)
	if image == "" || strings.Contains(image, "@sha256:") {
		return false
	}
	lastSlash := strings.LastIndex(image, "/")
	lastColon := strings.LastIndex(image, ":")
	if lastColon <= lastSlash {
		return true
	}
	return strings.EqualFold(image[lastColon+1:], "latest")
}

func isManifestFile(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml", ".json":
		return true
	default:
		return false
	}
}

func kubectlGetResource(ctx context.Context, kubectl string, options Options, resource string, namespaced bool) ([]byte, error) {
	args := kubectlBaseArgs(options, "get", resource)
	if namespaced {
		if strings.TrimSpace(options.Namespace) != "" {
			args = append(args, "--namespace", strings.TrimSpace(options.Namespace))
		} else if options.AllNamespaces {
			args = append(args, "--all-namespaces")
		}
	}
	args = append(args, "-o", "yaml")
	return kubectlOutput(ctx, kubectl, args)
}

func kubectlOutput(ctx context.Context, kubectl string, args []string) ([]byte, error) {
	command := exec.CommandContext(ctx, kubectl, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return nil, fmt.Errorf("%s %s: %s", kubectl, strings.Join(args, " "), message)
	}
	return output, nil
}

func kubectlBaseArgs(options Options, args ...string) []string {
	result := make([]string, 0, len(args)+4)
	if strings.TrimSpace(options.Kubeconfig) != "" {
		result = append(result, "--kubeconfig", strings.TrimSpace(options.Kubeconfig))
	}
	if strings.TrimSpace(options.Context) != "" {
		result = append(result, "--context", strings.TrimSpace(options.Context))
	}
	return append(result, args...)
}

func kubectlReadFinding(resource string, err error) report.Finding {
	return finding(
		"K8S020",
		"Unable to read Kubernetes resource",
		"medium",
		"scanner",
		"kubectl:get/"+resource,
		"KubernetesResource",
		resource,
		"",
		err.Error(),
		"Verify kubectl connectivity and RBAC permissions for this resource type.",
	)
}

func sortFindings(findings []report.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File == findings[j].File {
			if findings[i].ResourceKind == findings[j].ResourceKind {
				return findings[i].ResourceName < findings[j].ResourceName
			}
			return findings[i].ResourceKind < findings[j].ResourceKind
		}
		return findings[i].File < findings[j].File
	})
}

func reportProgress(progress func(string), format string, args ...any) {
	if progress == nil {
		return
	}
	progress(fmt.Sprintf(format, args...))
}
