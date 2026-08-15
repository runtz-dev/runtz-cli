# Changelog

All notable changes to the runtz CLI are documented here. Versions follow
`1.0.0-rc1 → 1.0.0-rc2 → ... → 1.0.0`, then regular semver.
(Releases rc4–rc7 were tagged without changelog entries; see the GitHub
release notes for those.)

## [Unreleased]

### Fixed

- `runtz host` on Windows now exits with the clear message
  `Host scanning is not supported on Windows` instead of attempting to read
  Linux's `/etc/os-release`.

## [1.0.0-rc8]

### Added

- `runtz login` — verifies a workspace token against the platform
  (`GET /api/v1/keys/verify`, runtz ≥ 1.0.0-rc12) and stores it in
  `os.UserConfigDir()/runtz/config.json` (dir `0700`, file `0600`), so scan
  commands no longer need `--token`. A self-hosted `--endpoint` is stored
  alongside the token and kept across logout/re-login. Reads the token from
  a hidden prompt on a TTY, from stdin when piped, or from `--token`.
- `runtz logout` — removes the stored token (keeps a stored self-hosted
  endpoint) and warns when `RUNTZ_TOKEN` is still set in the environment.
- `runtz whoami` — shows the workspace, key name/prefix/expiry, endpoint and
  where the current token comes from (flag, environment or stored login).
- `RUNTZ_CONFIG_DIR` overrides the config directory.

### Changed

- Scan commands resolve credentials as `--token` > `RUNTZ_TOKEN` (or the
  deprecated `RUNTZ_API_KEY`) > stored login, so CI keeps passing secrets
  explicitly while interactive use is just `runtz host`.
- The no-token error now points to the fix:
  `no token configured: run 'runtz login', pass --token, or set RUNTZ_TOKEN`.
- `runtz <cmd> --help` no longer echoes a token set in the environment as
  the `--token` flag default.

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
