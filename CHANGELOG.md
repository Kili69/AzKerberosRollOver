# Changelog

All notable changes to this project are documented in this file.

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
