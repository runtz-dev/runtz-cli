# Changelog

All notable changes to the runtz CLI are documented here. Versions follow
`1.0.0-rc1 → 1.0.0-rc2 → ... → 1.0.0`, then regular semver.

## [1.0.0-rc3]

### Fixed

- `install.sh`: `resolve_newest_tag`'s `grep -m1` closed its input pipe as
  soon as it matched, SIGPIPE-ing the upstream `curl`; combined with
  `pipefail` this silently killed the script on every run that needed the
  "no stable release yet" fallback (i.e. every run right now, since only
  `-rc` releases exist). Dropped `-m1` — `per_page=1` already limits the
  API response to one release, so the match is unaffected.
- `install.sh`: the sudo-vs-direct-write check used `[ -w "$INSTALL_DIR" ]`,
  which is false for a directory that doesn't exist yet (e.g. a fresh
  `RUNTZ_INSTALL_DIR=$HOME/.local/bin`, the documented custom-directory
  example), forcing an unnecessary `sudo` prompt. Now tries `mkdir -p`
  first and only escalates if that — or the resulting directory's
  writability — actually requires it.

## [1.0.0-rc2]

### Changed

- Installer moved from `get.runtz.dev` to `https://runtz.dev/install.sh`.
- `install.sh` now verifies the downloaded binary's SHA-256 against the
  release's `checksums.txt` (matching `runtz update`), guards for missing
  `curl`/`sha256sum`/`shasum`, skips `sudo` when already root, and retries
  the download once on a transient failure.

## [1.0.0-rc1]

Initial public release of the CLI as its own repository (split out from
`runtz-dev/runtz`).

### Added

- `sca`, `sast`, `host`, `container` and `k8s` scans that send results to a
  runtz engine.
- `runtz update` self-updater (`--check`, `--yes`) with SHA-256 verification of
  the downloaded binary.
- CI/CD severity gates on every scan (`--critical-threshold`, `--high-threshold`,
  `--medium-threshold`, `--low-threshold` and matching `RUNTZ_*_THRESHOLD` env
  vars) that exit with code `3` when tripped.
