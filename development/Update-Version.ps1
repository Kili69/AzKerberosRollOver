<#
.SYNOPSIS
Prepares the version metadata and changelog for a Git commit.

.DESCRIPTION
This development helper is called by the repository-managed pre-commit and
pre-merge-commit hooks. It calculates the next version from the configured
major and minor values, the current local date, and the highest same-day
counter found in the commit parents.

The script synchronizes the .VERSION metadata and $ScriptVersion assignment in
azKerberosRollover.ps1, updates the version badge in README.md, generates a
CHANGELOG.md entry from the staged Git changes, writes the files as UTF-8
without a byte-order mark, and stages the generated files.

The generated changelog entry is idempotent. Re-running the hook for the same
pending version replaces that version's existing entry instead of appending a
duplicate.

.EXAMPLE
.\Update-Version.ps1

Calculates the next version and prepares the generated files for a commit.

.NOTES
Run this script from a Git working tree. It intentionally modifies and stages
azKerberosRollover.ps1, README.md, and CHANGELOG.md.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$scriptPath = Join-Path $repoRoot 'azKerberosRollover.ps1'
$changelogPath = Join-Path $repoRoot 'CHANGELOG.md'
$readmePath = Join-Path $repoRoot 'README.md'

# Regex breakdown:
# (?m)                         enables multiline mode so ^ and $ apply per line.
# ^\.VERSION\s+               requires a line starting with the literal .VERSION
#                              followed by one or more whitespace characters.
# (?<major>\d+)\.(?<minor>\d+) captures numeric major and minor components; the
#                              escaped dot sequences are literal separators.
# (?<date>\d{8})              captures the eight-digit yyyyMMdd date.
# (?:\.(?<counter>\d+))?      optionally captures a dot and numeric daily counter.
# \s*$                        permits trailing whitespace before the line ends.
$versionPattern = '(?m)^\.VERSION\s+(?<major>\d+)\.(?<minor>\d+)\.(?<date>\d{8})(?:\.(?<counter>\d+))?\s*$'

# Use the same deterministic encoding for every generated text file.
$utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)

function Get-VersionMatch {
    <#
    .SYNOPSIS
    Finds and validates version metadata in script content.

    .DESCRIPTION
    Applies the script-wide version pattern and returns the Match object so the
    caller can read the named major, minor, date, and counter groups.

    .PARAMETER Content
    The complete text in which to locate the .VERSION metadata line.

    .PARAMETER Source
    A human-readable source identifier included in validation errors.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content,

        [Parameter(Mandatory = $true)]
        [string]$Source
    )

    $match = [regex]::Match($Content, $versionPattern)
    if (-not $match.Success) {
        throw "No supported version was found in $Source."
    }

    return $match
}

# Resolve all project files relative to this script so the hook works from any directory.
if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
    throw "Versioned script not found: $scriptPath"
}

$scriptContent = [System.IO.File]::ReadAllText($scriptPath)
$workingVersion = Get-VersionMatch -Content $scriptContent -Source $scriptPath

$date = Get-Date -Format 'yyyyMMdd'
$counter = 1

# HEAD is the parent for a regular commit. During a merge, MERGE_HEAD contains
# the additional parent revisions whose counters must also be considered.
$parentRevisions = @('HEAD')
$mergeHeadPath = Join-Path $repoRoot '.git\MERGE_HEAD'
if (Test-Path -LiteralPath $mergeHeadPath -PathType Leaf) {
    $parentRevisions += [System.IO.File]::ReadAllLines($mergeHeadPath)
}

foreach ($revision in $parentRevisions) {
    # Read the committed script directly from each parent without changing the working tree.
    $parentContent = & git -C $repoRoot show "${revision}:azKerberosRollover.ps1" 2>$null
    if ($LASTEXITCODE -ne 0) {
        # A new repository may not have a readable parent yet; counter 1 remains valid.
        continue
    }

    $parentVersion = Get-VersionMatch -Content ($parentContent -join "`n") -Source "${revision}:azKerberosRollover.ps1"
    if ($parentVersion.Groups['date'].Value -eq $date -and $parentVersion.Groups['counter'].Success) {
        # Selecting the maximum prevents a merge from reusing either parent's version.
        $counter = [Math]::Max($counter, [int]$parentVersion.Groups['counter'].Value + 1)
    }
}

# Major and minor come from the working copy, while date and counter are generated.
$version = '{0}.{1}.{2}.{3}' -f `
    $workingVersion.Groups['major'].Value, `
    $workingVersion.Groups['minor'].Value, `
    $date, `
    $counter

$scriptContent = [regex]::Replace(
    $scriptContent,
    $versionPattern,
    ".VERSION $version",
    1
)

# Regex breakdown:
# (?m)                  enables line-based ^ and $ anchors.
# ^\$ScriptVersion      requires the literal PowerShell variable name at line start.
# \s*=\s*               permits optional whitespace around the assignment operator.
# "[^"]*"               matches one complete double-quoted value without crossing its quote.
# \s*$                  permits trailing whitespace before the line ends.
$scriptVersionPattern = '(?m)^\$ScriptVersion\s*=\s*"[^"]*"\s*$'
if (-not [regex]::IsMatch($scriptContent, $scriptVersionPattern)) {
    throw 'The $ScriptVersion assignment was not found.'
}

$scriptContent = [regex]::Replace(
    $scriptContent,
    $scriptVersionPattern,
    "`$ScriptVersion = `"$version`"",
    1
)

if (-not (Test-Path -LiteralPath $readmePath -PathType Leaf)) {
    throw "README not found: $readmePath"
}

$readmeContent = [System.IO.File]::ReadAllText($readmePath)

# Regex breakdown:
# (?<prefix>...)                    captures the fixed shields.io badge URL prefix.
# \d+\.\d+\.\d{8}\.\d+             matches the displayed generated version.
# (?<suffix>-[A-Fa-f0-9]+)         captures the dash and hexadecimal badge color.
# Named prefix and suffix groups let the replacement change only the version.
$versionBadgeRegex = [regex]::new(
    '(?<prefix>https://img\.shields\.io/badge/version-)\d+\.\d+\.\d{8}\.\d+(?<suffix>-[A-Fa-f0-9]+)'
)
if (-not $versionBadgeRegex.IsMatch($readmeContent)) {
    throw 'The README version badge was not found.'
}

$readmeContent = $versionBadgeRegex.Replace(
    $readmeContent,
    {
        param($match)

        return "$($match.Groups['prefix'].Value)$version$($match.Groups['suffix'].Value)"
    },
    1
)

# Read only staged changes because the generated changelog must describe the commit
# being prepared, not unrelated modifications that remain in the working tree.
# --diff-filter includes every status the mapping below understands.
$stagedChanges = & git -C $repoRoot diff --cached --name-status --diff-filter=ACDMRTUXB
if ($LASTEXITCODE -ne 0) {
    throw 'Could not read the staged changes.'
}

$changeDescriptions = foreach ($change in $stagedChanges) {
    # Git separates status and paths with tabs. PowerShell's -split operator uses
    # regex semantics, but the interpolated `t is one literal tab character.
    $parts = $change -split "`t"
    $status = $parts[0].Substring(0, 1)
    $description = switch ($status) {
        'A' { 'Added' }
        'C' { 'Copied' }
        'D' { 'Deleted' }
        'M' { 'Modified' }
        'R' { 'Renamed' }
        'T' { 'Type changed' }
        'U' { 'Unmerged' }
        'X' { 'Unknown change' }
        'B' { 'Pairing broken' }
        default { 'Changed' }
    }

    # Rename and copy records contain old and new paths; other statuses contain one path.
    if ($parts.Count -ge 3) {
        "- ${description}: ``$($parts[1])`` to ``$($parts[2])``"
    }
    else {
        "- ${description}: ``$($parts[1])``"
    }
}

if (-not $changeDescriptions) {
    $changeDescriptions = '- Commit without staged project changes.'
}

$entryDate = Get-Date -Format 'yyyy-MM-dd'
$entry = "## [$version] - $entryDate`r`n`r`n### Changed`r`n`r`n"
$entry += ($changeDescriptions -join "`r`n") + "`r`n`r`n"

if (Test-Path -LiteralPath $changelogPath -PathType Leaf) {
    $changelogContent = [System.IO.File]::ReadAllText($changelogPath)
}
else {
    $changelogContent = "# Changelog`r`n`r`nAll notable changes to this project are documented in this file.`r`n`r`n"
}

# Re-running the hook before a commit uses the same version. Replace that version's
# complete changelog section so retries never create duplicate entries.
$escapedVersion = [regex]::Escape($version)

# Regex breakdown:
# (?ms)                    enables multiline anchors and lets dot match newlines.
# ^## \[...\] -            starts at the release heading for this literal version.
# .*?                      consumes the section body non-greedily.
# (?=^## \[|\z)            stops before the next release heading or absolute end
#                           of input without consuming that boundary.
$existingEntryPattern = "(?ms)^## \[$escapedVersion\] - .*?(?=^## \[|\z)"
if ([regex]::IsMatch($changelogContent, $existingEntryPattern)) {
    $changelogContent = [regex]::Replace($changelogContent, $existingEntryPattern, $entry, 1)
}
else {
    $firstReleaseIndex = $changelogContent.IndexOf('## [')
    if ($firstReleaseIndex -ge 0) {
        $changelogContent = $changelogContent.Insert($firstReleaseIndex, $entry)
    }
    else {
        if (-not $changelogContent.EndsWith("`n")) {
            $changelogContent += "`r`n"
        }
        $changelogContent += "`r`n$entry"
    }
}

# Write all generated content only after every calculation and validation succeeds.
[System.IO.File]::WriteAllText($scriptPath, $scriptContent, $utf8WithoutBom)
[System.IO.File]::WriteAllText($changelogPath, $changelogContent, $utf8WithoutBom)
[System.IO.File]::WriteAllText($readmePath, $readmeContent, $utf8WithoutBom)

# Ensure generated metadata is part of the same commit as the staged source changes.
& git -C $repoRoot add -- $scriptPath $changelogPath $readmePath
if ($LASTEXITCODE -ne 0) {
    throw 'Could not stage the updated version, changelog, and README badge.'
}

Write-Host "Prepared version $version."
