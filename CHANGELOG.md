# Changelog

All notable changes to the runtz CLI are documented here. Versions follow
`1.0.0-rc1 → 1.0.0-rc2 → ... → 1.0.0`, then regular semver.

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
