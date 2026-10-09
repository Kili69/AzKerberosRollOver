# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [1.0.20261009.12] - 2026-10-09

### Fixed

- Resolved the Entra Connect server computer by distinguished name before reading
  `tokenGroups`, ensuring the SYSTEM permission preflight uses the LDAP base search
  required for this constructed Active Directory attribute.
- Preserved structured authentication results and complete background-job diagnostics
  so job error-stream records no longer hide the underlying Microsoft Entra error or
  incorrectly prove that password synchronization failed.
- Restored SYSTEM background jobs with explicit AzureADSSO cloud and on-premises
  credentials because Windows does not support the alternate-credential process
  creation used by credentialed background jobs when the caller is LocalSystem.
- Removed the unnecessary alternate-logon service and local-rights preflight; the
  dedicated worker account requires neither local nor batch logon rights.
- Preserved an explicitly advanced same-day working version so repeated development
  builds remain distinguishable before they are committed.
- Changed log-file timestamps to UTC in ISO 8601 format for easier correlation with
  Microsoft Entra sign-in logs.
- Replaced the 15-minute freshness check with a strict `AzureADSSOAcc` `pwdLastSet`
  comparison against the value saved before the rollover, using the same PDC
  emulator for both reads.

### Changed

- Modified: `CHANGELOG.md`
- Modified: `EVENTID.md`
- Modified: `README.md`
- Modified: `azKerberosRollover.ps1`



## [1.0.20261009.10] - 2026-10-09

### Changed

- Modified: `.github/workflows/release.yml`
- Modified: `CHANGELOG.md`
- Modified: `DEVELOPER.md`
- Modified: `development/Test-Changelog.ps1`
- Modified: `development/Update-Version.ps1`


## [1.0.20261009.9] - 2026-10-09

### Added

- Added standard PowerShell verbose output, including the log file path and verbose
  output from the AzureADSSO background job.
- Added a detailed WhatIf validation summary with resolved identities, effective
  permissions, TGT status, synchronization strategy, and planned actions.
- Added AADSTS-based authentication failure classification with immediate termination
  and a shared exit code for MFA and Conditional Access failures.
- Added phase-specific errors that distinguish Microsoft Entra authentication failures
  from access denied while running `Update-AzureADSSOForest`.
- Corrected the delegated `AzureADSSOAcc` permission from Change Password to Write,
  which is required by `Update-AzureADSSOForest`.
- Added support for resolving the rollover account as a `sAMAccountName`, UPN, or
  `DOMAIN\sAMAccountName`.
- Added an unconditional startup version display.
- Added preflight checks for the executing principal's Reset Password permission on
  the rollover account and the rollover account's Write/Reset Password permissions
  on `AzureADSSOAcc`.
- Added `Set-AzKerberosRolloverPermissions.ps1` to protect the rollover user with the
  domain's `AdminSDHolder` DACL, grant Reset Password to the Entra Connect computer,
  and delegate the rollover account on `AzureADSSOAcc`.
- Added `-Force` to the permission setup script to suppress ACL confirmation prompts
  without bypassing `-WhatIf`.
- Added an unconditional version display to the permission setup script and replaced
  ActiveDirectory cmdlet-import noise with one concise module status message.
- Added comprehensive inline and function-level documentation to the permission setup
  script, including its identity resolution, ACL, AdminSDHolder, and delegation logic.
- Documented every regular expression and regex-based split operation in the
  permission setup script.
- Added comprehensive inline documentation to the rollover script, including an
  explanation for every regular expression and regex-based split operation.
- Added comprehensive function and inline documentation to the scheduled-task setup
  script, including an explanation for every regular expression.
- Added `New-AzKerberosRolloverScheduleTask.ps1` with interactive defaults, daily,
  weekly, and hourly triggers, SYSTEM execution, optional log and verbose arguments,
  and support for `-WhatIf` and `-Force`.
- Added detection of an existing `AzKerberosRollOver` task so its parameters are
  updated with `Set-ScheduledTask` instead of registering a replacement.
- Improved interactive scheduled-task path validation with a clear missing-script
  message and a repeated prompt instead of terminating immediately.
- Changed the interactive task setup path default to the parent directory when the
  current directory is named `tools`.
- Added Active Directory validation for the scheduled task's rollover account, with
  repeated prompting for invalid interactive input and a terminating parameter error.
- Added explicit `TimeToRun` validation that repeats invalid interactive input and
  terminates for an invalid parameter value.
- Added explicit `Repeat` validation that repeats invalid interactive input and
  terminates for an invalid parameter value.
- Added `LogPath` validation that repeats invalid interactive input, allows an empty
  value for the rollover script default, and terminates for an invalid parameter.
- Added a scheduled task description containing the rollover purpose, account, script
  path, schedule, and Microsoft Kerberos rollover documentation link.
- Added a one-hour execution time limit to terminate stalled scheduled task runs.

### Changed

- Replaced the inverse `DoNotStartSync` switch with `StartEntraConnectSync`.
- Disabled Entra Connect delta synchronization by default; it now runs only when
  `StartEntraConnectSync` is specified.
- Limited ADSync module loading to executions that request an Entra Connect sync.
- Corrected the script copyright metadata and consolidated runtime prerequisites in
  the comment-based help description.
- Evaluated the local computer account and its AD groups during permission preflight
  when the rollover task runs as local SYSTEM.
- Added automatic GitHub release creation with a curated installation package when
  `dev` is pushed to `main`.
- Moved development-only version and changelog scripts out of the operational
  `tools` directory.
- Added version, branch, and Buy Me a Coffee badges to the README.
- Renamed the developer and event ID references to `DEVELOPER.md` and `EVENTID.md`.
- Added comprehensive documentation for the development automation scripts.
- Synchronized the README version badge through the version update hook.

### Fixed

- Displayed startup and invalid-operation failures in the console.
- Logged event-source creation failures directly to the log file instead of writing
  them through the unsuitable `Application` event source.
- Resolved UPN and `DOMAIN\sAMAccountName` inputs to the correct AD user, domain, and
  credentials before resetting the password.
- Propagated AzureADSSO background-job failures to the main workflow instead of
  reporting success and continuing with password verification.
- Removed the `Wait-Job` status table from normal console output and preserved the
  original exception message in final error reporting.
- Supported Active Directory module versions that return `tokenGroups` entries as
  `SecurityIdentifier` objects instead of raw SID byte arrays.
- Read the final `AzureADSSOAcc` password timestamp from the PDC emulator of the
  account's actual domain.
- Prevented interrupted or incomplete rollover runs from reporting successful
  completion.

## [0.1.20261009.1] - 2026-10-09

### Changed

- Added: `.github/workflows/changelog.yml`
- Modified: `EventID.md`
- Modified: `README.md`
- Modified: `azKerberosRollover.ps1`
- Modified: `developer.md`
- Added: `tools/Test-Changelog.ps1`

## [0.1.20261008.2] - 2026-10-08

### Changed

- Adopted the MIT license.
- Expanded operational, monitoring, and event ID documentation.

### Fixed

- Returned a nonzero process exit code when the rollover workflow fails.
- Corrected event ID descriptions to match the script behavior.

## [0.1.20261008.1] - 2026-10-08

### Changed

- Restructured the project documentation around installation, operation, monitoring,
  troubleshooting, and development.

## [0.1.20261007.1] - 2026-10-07

### Added

- Added project branding and the AzKerberosRollOver logo.
- Added developer guidance.

### Changed

- Modernized and expanded the README.

## [0.1.20260929.4] - 2026-09-29

### Added

- Added `WhatIf` support for validating prerequisites without changing passwords,
  starting synchronization, updating seamless SSO, or writing logs.
- Added comment-based help and developer documentation.

### Changed

- Improved parameter validation, error handling, logging, and rollover verification.

## [0.1.20260929.3] - 2026-09-29

### Added

- Added repository Git hooks, changelog maintenance, and automatic version tooling.

## [0.1.20260929.2] - 2026-09-29

### Added

- Added merge-commit version automation.

## [0.1.20260929.1] - 2026-09-29

### Added

- Added initial commit-version automation and pre-commit integration.

## [0.1.20251110] - 2025-11-10

### Added

- Added `IgnoreTGTLifetimeCheck` to allow an explicitly forced rollover within the
  configured TGT lifetime.

## [0.1.20251107] - 2025-11-07

### Changed

- Ran the AzureADSSO update in a separate PowerShell process under the rollover
  account, enabling device-aware Conditional Access scenarios.

## [0.1.20251014] - 2025-10-14

### Added

- Added forest-wide discovery of `AzureADSSOAcc` through a Global Catalog.

### Fixed

- Corrected error handling for cross-domain `AzureADSSOAcc` deployments.

## [0.1.20251007] - 2025-10-07

### Changed

- Expanded error handling and diagnostic logging.

## [0.1.20251006] - 2025-10-06

### Added

- Added event IDs for more precise operational monitoring.

### Changed

- Moved timing validation into the runtime workflow and used safe bounded values for
  unsupported input.
- Allowed a TGT lifetime of zero to bypass the age check.

### Fixed

- Corrected log file naming when running in PowerShell ISE.

## [0.1.20250818] - 2025-08-18

### Added

- Added `TGTLifetimeHours` to prevent rollover while tickets encrypted with the
  current key may still be valid.

### Fixed

- Corrected minor rollover and validation issues.

## [0.1.20250509] - 2025-05-09

### Added

- Added validation for the rollover account UPN, AzureADSSO module path, log path,
  and rollover account name.
- Added `DoNotStartSync` to optionally skip the Azure AD synchronization.
- Added retry handling for debug log sharing violations.

## [0.1.20250508] - 2025-05-08

### Added

- Added PowerShell ISE log file name detection.
- Added bounds for `AzureSyncWaitTime`.

## [0.1.20250504] - 2025-05-04

### Changed

- Expanded error logging.

## [0.1.20250501] - 2025-05-01

### Added

- Added a configurable log file location.

### Changed

- Improved code comments and formatting.

## [0.1] - 2021

### Added

- Added the initial script.

[Unreleased]: https://github.com/Kili69/AzKerberosRollOver/compare/v1.0.20261009.12...HEAD
[1.0.20261009.12]: https://github.com/Kili69/AzKerberosRollOver/releases/tag/v1.0.20261009.12
[1.0.20261009.10]: https://github.com/Kili69/AzKerberosRollOver/releases/tag/v1.0.20261009.10
[1.0.20261009.9]: https://github.com/Kili69/AzKerberosRollOver/releases/tag/v1.0.20261009.9
[0.1.20261008.2]: https://github.com/Kili69/AzKerberosRollOver/commit/55cca79077179e307f13cc95efac04f50a8a76c4
[0.1.20261008.1]: https://github.com/Kili69/AzKerberosRollOver/commit/fd1e89758b08519714fbf22b27709be380e713cf
[0.1.20261007.1]: https://github.com/Kili69/AzKerberosRollOver/commit/f7461b10e7050d0a1bae7721b82e21115d6bf347
[0.1.20260929.4]: https://github.com/Kili69/AzKerberosRollOver/commit/76ce567c7731997afb00c0968eac14233c73cc7a
[0.1.20260929.3]: https://github.com/Kili69/AzKerberosRollOver/commit/610fe61
[0.1.20260929.2]: https://github.com/Kili69/AzKerberosRollOver/commit/b6ba44b
[0.1.20260929.1]: https://github.com/Kili69/AzKerberosRollOver/commit/2e8f44b
[0.1.20251110]: https://github.com/Kili69/AzKerberosRollOver/commit/f5f43f8
[0.1.20251107]: https://github.com/Kili69/AzKerberosRollOver/commit/a5231e6
[0.1.20251014]: https://github.com/Kili69/AzKerberosRollOver/commit/ad7ac56
[0.1.20251007]: https://github.com/Kili69/AzKerberosRollOver/commit/cef14c0
[0.1.20251006]: https://github.com/Kili69/AzKerberosRollOver/commit/4a86a64
[0.1.20250818]: https://github.com/Kili69/AzKerberosRollOver/commit/059c291
[0.1.20250509]: https://github.com/Kili69/AzKerberosRollOver/commit/72e9dea
[0.1.20250508]: https://github.com/Kili69/AzKerberosRollOver/commit/61c0186
[0.1.20250504]: https://github.com/Kili69/AzKerberosRollOver/commit/5faa485
[0.1.20250501]: https://github.com/Kili69/AzKerberosRollOver/commit/4d12688
