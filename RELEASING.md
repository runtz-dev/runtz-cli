# Releasing runtz-cli

Releases are driven by CI. Publishing a GitHub Release runs
`.github/workflows/release.yml`, which publishes the binaries to GitHub Releases
(via GoReleaser) and the `runtzdev/runtz-cli` multi-arch image to Docker Hub.
Versions follow `1.0.0-rc1 → 1.0.0-rc2 → ... → 1.0.0`, then regular semver.

## 0. Prerequisites (one-time)

Configured on the `runtz-dev` org:

- GitHub Actions **variable** `DOCKER_LOGIN` and **secret** `DOCKER_PASS`
  (Docker Hub push access to the `runtzdev` org).
- Self-hosted runners labelled `runtz-runners`.
- GoReleaser uses the built-in `GITHUB_TOKEN`; no extra token needed.

## 1. Cut the release

1. Open a PR into `main` bumping `VERSION` and updating `CHANGELOG.md`, and
   merge it. Release Drafter keeps a draft release up to date from merged PRs
   (categorized by their labels).
2. Open the draft release, set its tag to `v$(cat VERSION)`, and publish it
   (mark it a pre-release for `-rc` versions).

Publishing the release triggers `release.yml`:

- **binaries** — GoReleaser builds `runtz_{linux,darwin}_{amd64,arm64}` +
  `checksums.txt` and attaches them to the GitHub Release (prerelease auto-detected
  from the `-rc` suffix). The installer (`curl -fsSL https://get.runtz.dev | bash`)
  and `runtz update` consume these assets.
- **image** — builds and pushes `runtzdev/runtz-cli:<version>` (and `:latest`
  for stable versions).

## 2. After the release

- Verify: `curl -fsSL https://get.runtz.dev | bash && runtz version`.
- Verify: `runtz update --check` on the previous version reports the new one.
- Verify: `docker run --rm runtzdev/runtz-cli:$(cat VERSION) version`.

## Manual fallback

From a checkout with Go + GoReleaser + `GITHUB_TOKEN`:

```bash
goreleaser release --clean
```
