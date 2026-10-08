# Changelog

All notable changes to this project are documented in this file.

## [0.1.20261008.1] - 2026-10-08

### Changed

- Modified: `README.md`
- Modified: `developer.md`

## [0.1.20261007.1] - 2026-10-07

### Changed

- Modified: `README.md`
- Modified: `developer.md`
- Added: `docs/assets/azkerberosrollover-logo.png`

## [0.1.20260929.4] - 2026-09-29

### Changed

- Modified: `README.md`
- Modified: `azKerberosRollover.ps1`
- Added: `developer.md`

## [0.1.20260929.3] - 2026-09-29

### Changed

- Added: `.githooks/pre-commit`
- Added: `.githooks/pre-merge-commit`
- Added: `CHANGELOG.md`
- Modified: `README.md`
- Modified: `azKerberosRollover.ps1`
- Added: `tools/Update-Version.ps1`

## [0.1.20260929.2] - 2026-09-29

### Changed

- Added: `.githooks/pre-merge-commit`
- Modified: `README.md`

## [0.1.20260929.1] - 2026-09-29

### Changed

- Added: `.githooks/pre-commit`
- Added: `CHANGELOG.md`
- Modified: `README.md`
- Added: `tools/Update-Version.ps1`

## [0.1.20250509] - 2025-05-09

### Changed

- Added validation for the rollover account UPN, AzureADSSO module path, log path, and SAM account name.
- Added `DoNotStartSync` to optionally skip the Azure AD synchronization.
- Added retries for debug log sharing violations.

## [0.1.20250508] - 2025-05-08

### Changed

- Added PowerShell ISE log file name detection.
- Restricted `AzureSyncWaitTime` to 15 through 120 seconds.

## [0.1.20250504] - 2025-05-04

### Changed

- Added additional error logging.

## [0.1.20250501] - 2025-05-01

### Changed

- Improved code comments and formatting.
- Added a parameter for the log file location.

## [0.1] - 2021

### Added

- Initial version of the script.
