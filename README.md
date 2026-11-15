<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://runtz.dev/brand/runtz-logo-dark.svg">
  <img src="https://runtz.dev/brand/runtz-logo-light.svg" alt="runtz" width="220">
</picture>

# runtz-cli

[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)
[![Docker Hub](https://img.shields.io/badge/Docker%20Hub-runtzdev-2496ED?logo=docker&logoColor=white)](https://hub.docker.com/r/runtzdev/runtz-cli)
[![Docs](https://img.shields.io/badge/Docs-runtz.dev-2f7eff)](https://runtz.dev/docs)

`runtz` is the DevSecOps scanner CLI for the [runtz platform](https://github.com/runtz-dev/runtz).
It runs SCA, SAST, host, container and Kubernetes scans and sends the results to
your runtz engine (self-hosted or the SaaS at `https://engine.runtz.dev`).

## Install

```bash
curl -fsSL https://runtz.dev/install.sh | bash
runtz version
```

Windows (PowerShell):

```powershell
irm https://runtz.dev/install.ps1 | iex
runtz version
```

Or download a binary from the [releases page](https://github.com/runtz-dev/runtz-cli/releases)
(`runtz_<os>_<arch>` for linux/darwin, amd64/arm64, plus `runtz_windows_amd64.exe`),
or run the Docker image:

```bash
docker run --rm runtzdev/runtz-cli:latest --help
```

## Update

The CLI updates itself in place, verifying the download's SHA-256 against the
release checksums:

```bash
runtz update          # prompts before replacing the binary
runtz update --yes    # no prompt (automation)
runtz update --check  # only report if a newer version exists (exit 3 if so)
```

If the binary lives in a root-owned directory such as `/usr/local/bin`,
`runtz update` retries the install through `sudo` and asks for your password,
so you don't need to run `sudo runtz update`. Without a terminal (CI,
scripts) it fails with a hint instead of prompting.

## Log in once

`runtz login` verifies a workspace token (generated in the platform) and stores
it in `~/.config/runtz/config.json` (0600), so scan commands no longer need
`--token`:

```bash
runtz login                                  # paste the token at a hidden prompt
runtz login --token rtz_live_...             # non-interactive
runtz login --endpoint http://localhost:8080 # self-hosted: endpoint is stored too
runtz whoami                                 # workspace + where the token comes from
runtz whoami --json                          # machine-readable integration status
runtz logout                                 # remove the stored token
```

The token is resolved in this order — an explicit flag or environment variable
(the CI/CD path) always beats the stored login:

1. `--token` flag
2. `RUNTZ_TOKEN` environment variable
3. `runtz login` stored token

## Scans

After `runtz login` (or with `RUNTZ_TOKEN` set), scans are just:

```bash
runtz sca ./
runtz sast ./
runtz host
runtz container ubuntu:22.04
runtz k8s
```

`--endpoint` defaults to the Runtz SaaS backend; pass it (or store it via
`runtz login --endpoint ...`) only for self-hosted deployments.

- **sca** — dependency manifests (JavaScript/TypeScript, Python, Go, Java/Kotlin,
  Ruby, PHP, Rust, C#/.NET) against GitHub Global Security Advisories.
- **sast** — source code rules for committed secrets, dynamic code execution,
  disabled TLS verification and weak hashing.
- **host** — installed OS packages (dpkg/rpm/apk) matched against OSV. With
  several kernels installed, only the running one is matched.
- **container** — OS packages inside an image (pulled without Docker, or `--local`).
- **k8s** — a live cluster (current kubectl context) or manifests (positional path).

`--endpoint`/`--token` also read from `RUNTZ_ENDPOINT`/`RUNTZ_TOKEN`. Run
`runtz help <command>` for the full flag and environment reference.

In CI/CD, skip `runtz login` and pass the token from a secret instead —
`--token "$RUNTZ_TOKEN"` or just export `RUNTZ_TOKEN`.

## CI/CD severity gates

Any scan can fail the pipeline when it finds too many issues at a given severity.
The flags are optional; `0` (the default) means the gate is off.

```bash
# Fail the build on a single critical, or on 5+ highs:
runtz sca ./ \
  --endpoint "$RUNTZ_ENDPOINT" --token "$RUNTZ_TOKEN" \
  --critical-threshold 1 \
  --high-threshold 5
```

Flags (on every scan): `--critical-threshold N`, `--high-threshold N`,
`--medium-threshold N`, `--low-threshold N`, or the env vars
`RUNTZ_CRITICAL_THRESHOLD`, `RUNTZ_HIGH_THRESHOLD`, `RUNTZ_MEDIUM_THRESHOLD`,
`RUNTZ_LOW_THRESHOLD`.

**Exit codes:** `0` success · `1` execution error · `2` usage error ·
`3` a severity gate tripped (or `runtz update --check` found an update). The scan
results are always sent to the platform before the gate is evaluated, so a failed
gate still records the scan.

Example GitHub Actions step:

```yaml
- name: runtz SCA gate
  run: runtz sca ./ --critical-threshold 1 --high-threshold 1
  env:
    RUNTZ_ENDPOINT: https://engine.runtz.dev
    RUNTZ_TOKEN: ${{ secrets.RUNTZ_TOKEN }}
```

## Development

```bash
go test ./...
go run ./cmd/runtz --help
```

See [AGENTS.md](AGENTS.md) for the branch flow and contribution rules, and
[RELEASING.md](RELEASING.md) for how releases are cut.

## License

runtz-cli is source-available under the [Business Source License 1.1](LICENSE),
converting to MPL-2.0 four years after each release. For commercial licensing,
contact licensing@runtz.dev.

---

Copyright © 2026 Runtz · RAW DEVOPS LTDA (CNPJ 51.460.107/0001-53). All rights reserved.

## Cloud scanning

Run Runtz-owned, read-only GCP, AWS and Azure checks through the public
Runtz Security API. The CLI sends cloud credentials over HTTPS for validation
and scanning. This request-scoped API does not store those credentials; the CLI
then uploads checks, findings and coverage to your workspace.

```sh
runtz login
runtz gcp config
runtz gcp
# Or: runtz aws config / runtz aws
# Or: runtz azure config / runtz azure
```

The first interactive provider command opens setup if needed, then scans.
`config` by itself validates and saves without scanning. GCP asks for a project
ID and JSON key path; AWS asks for the account ID, IAM user access key, secret
and regions; Azure asks for the subscription, tenant ID, client ID and secret
value. Secrets are hidden at prompts. Existing login and other cloud configs
are preserved, including when running `runtz logout`.

On Linux, configuration is `~/.config/runtz/config.json` (`0700` directory,
`0600` file). macOS and Windows use `os.UserConfigDir()`. `RUNTZ_CONFIG_DIR`
overrides it. GCP stores an absolute key-file path, not a copy of the key.
AWS and Azure credentials are saved with owner-only permissions.

CI does not open prompts. Supply the provider's required flags and secret env vars:

```sh
# GCP: GOOGLE_APPLICATION_CREDENTIALS and RUNTZ_TOKEN from the CI secret manager
runtz gcp --project-id YOUR_PROJECT_ID
# AWS: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and RUNTZ_TOKEN
runtz aws --account-id YOUR_ACCOUNT_ID --regions us-east-1,sa-east-1
# Azure: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET and RUNTZ_TOKEN
runtz azure --subscription-id YOUR_SUBSCRIPTION_ID
```

Provider CLIs are only needed for optional setup instructions. The private Security collectors call
provider APIs and support the standard severity thresholds. Results are
uploaded before an enabled gate returns `3`. Missing permissions remain skipped
or errored checks, never passes. CLI results appear under **Cloud** with a CLI
source. Rerun locally or schedule in CI for new results. A scope already connected
through the site must be disconnected before switching to CLI mode.

Guides: [GCP](https://runtz.dev/docs/scans/google-cloud),
[AWS](https://runtz.dev/docs/scans/aws), [Azure](https://runtz.dev/docs/scans/azure).

### Security endpoint and check updates

Hosted commands use `https://security.runtz.dev`. An engine endpoint of
`https://engine-dev.runtz.dev` selects `https://security-dev.runtz.dev`.
The workspace API token is verified by Security against its configured engine;
the CLI checks that both services identify the same workspace.

For self-hosting, pass `--security-endpoint https://security.example.com` during
`config` to save it, or set `RUNTZ_SECURITY_ENDPOINT`. Explicit flag, environment,
then saved config determine the URL. HTTPS is required except for loopback HTTP
in local development. Security must set `RUNTZ_SECURITY_ENGINE_URL` to the same
engine as `--endpoint`; old engines without token verification are unsupported
for cloud scanning. The CLI never receives the internal Security service key.

The scan response streams heartbeats until completion. Disconnects/timeouts
require retrying the command. A new check requires deploying Security, with no
CLI update for compatible API changes. The CLI contains transport/result types,
not a snapshot of private collectors or rule implementations.
