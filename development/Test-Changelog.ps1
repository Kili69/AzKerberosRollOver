<#
.SYNOPSIS
Validates that every commit in a Git revision range contains a matching changelog entry.

.DESCRIPTION
This development and CI helper examines each commit between BaseRevision and
HeadRevision in chronological order. Every commit must modify CHANGELOG.md,
contain a supported .VERSION value in azKerberosRollover.ps1, and contain a
CHANGELOG.md release heading for that exact version.

When a push does not provide a usable base revision, the script calculates one
from the merge base of HeadRevision and the remote default branch. All detected
validation problems are collected so one run reports every affected commit.

.PARAMETER BaseRevision
The commit immediately before the revision range to validate. GitHub supplies
an all-zero value for some new branch pushes; the script handles that case by
calculating a merge base.

.PARAMETER HeadRevision
The newest commit in the revision range to validate.

.PARAMETER DefaultBranch
The repository's default branch name, without the origin/ prefix. It is used
only when BaseRevision is missing or invalid.

.EXAMPLE
.\Test-Changelog.ps1 -BaseRevision HEAD~1 -HeadRevision HEAD -DefaultBranch main

Validates the most recent commit.

.NOTES
This script is intended for development and CI use. It does not modify the
repository or the working tree.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BaseRevision,

    [Parameter(Mandatory = $true)]
    [string]$HeadRevision,

    [Parameter(Mandatory = $true)]
    [string]$DefaultBranch
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Git {
    <#
    .SYNOPSIS
    Runs Git and returns its output as an array of lines.

    .DESCRIPTION
    Redirects Git's error stream into the captured output and converts every
    nonzero exit code into a terminating PowerShell error that includes the
    command and Git diagnostics.

    .PARAMETER Arguments
    The individual arguments passed to the Git executable.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $output = @(& git @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "git $($Arguments -join ' ') failed:`n$($output -join "`n")"
    }

    return $output
}

function Test-GitRevision {
    <#
    .SYNOPSIS
    Tests whether a Git revision resolves to a commit.

    .DESCRIPTION
    Uses git cat-file with Git's ^{commit} peeling syntax. The suffix asks Git
    to resolve annotated tags and other commit-ish values to a commit object.
    It is Git revision syntax, not a PowerShell regular expression.

    .PARAMETER Revision
    A commit hash, branch, tag, or other Git commit-ish value to validate.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Revision
    )

    & git cat-file -e "$Revision`^{commit}" 2>$null
    return $LASTEXITCODE -eq 0
}

# The head must exist because every later comparison and file lookup depends on it.
if (-not (Test-GitRevision -Revision $HeadRevision)) {
    throw "Head revision '$HeadRevision' is unavailable."
}

# Regex breakdown:
# ^     starts at the beginning of the value.
# 0+    requires one or more zero characters.
# $     ends at the end of the value.
# GitHub uses a string of zeroes when a push event has no usable previous commit.
$zeroRevisionPattern = '^0+$'
if ($BaseRevision -match $zeroRevisionPattern -or -not (Test-GitRevision -Revision $BaseRevision)) {
    $remoteDefaultBranch = "origin/$DefaultBranch"
    if (-not (Test-GitRevision -Revision $remoteDefaultBranch)) {
        throw "Neither base revision '$BaseRevision' nor '$remoteDefaultBranch' is available."
    }

    # The merge base gives a stable start point for a new branch or incomplete push range.
    $BaseRevision = (Invoke-Git -Arguments @('merge-base', $remoteDefaultBranch, $HeadRevision))[0]
}

# --reverse returns the oldest commit first so validation output follows history order.
$commits = @(
    Invoke-Git -Arguments @('rev-list', '--reverse', "$BaseRevision..$HeadRevision")
)

if ($commits.Count -eq 0) {
    Write-Host 'No new commits require changelog validation.'
    exit 0
}

# Keep validating after an individual failure so CI reports every bad commit at once.
$failures = [System.Collections.Generic.List[string]]::new()

# Regex breakdown:
# (?m)                         enables multiline mode so ^ and $ apply per line.
# ^\.VERSION\s+               requires a line beginning with the literal .VERSION
#                              followed by one or more whitespace characters.
# (?<version>...)             captures the complete version in the named group "version".
# \d+\.\d+\.\d{8}\.\d+       requires major.minor.yyyyMMdd.counter; escaped dots
#                              are literal separators and \d{8} is the eight-digit date.
# \s*$                        permits trailing whitespace before the line ends.
$versionPattern = '(?m)^\.VERSION\s+(?<version>\d+\.\d+\.\d{8}\.\d+)\s*$'

foreach ($commit in $commits) {
    # -m exposes paths from every parent of a merge commit. Sorting removes duplicates.
    $changedPaths = @(
        Invoke-Git -Arguments @(
            'diff-tree',
            '--root',
            '--no-commit-id',
            '--name-only',
            '-r',
            '-m',
            $commit
        )
    ) | Sort-Object -Unique

    if ($changedPaths -notcontains 'CHANGELOG.md') {
        $failures.Add("$commit does not update CHANGELOG.md.")
        continue
    }

    # Read files from the commit itself rather than from the current working tree.
    $scriptContent = (
        Invoke-Git -Arguments @('show', "${commit}:azKerberosRollover.ps1")
    ) -join "`n"
    $versionMatch = [regex]::Match($scriptContent, $versionPattern)
    if (-not $versionMatch.Success) {
        $failures.Add("$commit does not contain a supported script version.")
        continue
    }

    $version = $versionMatch.Groups['version'].Value
    $changelogContent = (
        Invoke-Git -Arguments @('show', "${commit}:CHANGELOG.md")
    ) -join "`n"

    # Regex breakdown:
    # (?ms)                enables line-based anchors and lets dot match newlines.
    # ^## \[...\] -        requires a Markdown H2 heading with the version in brackets.
    # [regex]::Escape()    makes every dot in the generated version literal instead of
    #                       treating it as the regex wildcard character.
    # \d{4}-\d{2}-\d{2}   requires an ISO-style yyyy-MM-dd date.
    # [^\S\r\n]*\r?\n      accepts horizontal whitespace and either newline style.
    # (?<content>.*?)      captures the release notes non-greedily.
    # (?=^## \[|\z)        stops before the next release heading or end of input.
    $entryPattern = "(?ms)^## \[$([regex]::Escape($version))\] - \d{4}-\d{2}-\d{2}[^\S\r\n]*\r?\n(?<content>.*?)(?=^## \[|\z)"
    $entryMatch = [regex]::Match($changelogContent, $entryPattern)
    if (-not $entryMatch.Success) {
        $failures.Add("$commit updates CHANGELOG.md but has no entry for version $version.")
        continue
    }

    if ([string]::IsNullOrWhiteSpace($entryMatch.Groups['content'].Value)) {
        $failures.Add("$commit has an empty CHANGELOG.md entry for version $version.")
        continue
    }

    $unreleasedIndex = $changelogContent.IndexOf('## [Unreleased]')
    if ($unreleasedIndex -lt 0 -or $unreleasedIndex -gt $entryMatch.Index) {
        $failures.Add("$commit must place the Unreleased section before version $version.")
        continue
    }

    Write-Host "Validated $commit with changelog version $version."
}

if ($failures.Count -gt 0) {
    # Write every detailed failure before throwing one final error that fails the CI job.
    $failures | ForEach-Object { Write-Error $_ -ErrorAction Continue }
    throw "Changelog validation failed for $($failures.Count) commit(s). Enable the repository Git hooks and recreate the affected commits."
}

Write-Host "Validated changelog updates for $($commits.Count) commit(s)."
