[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$scriptPath = Join-Path $repoRoot 'azKerberosRollover.ps1'
$changelogPath = Join-Path $repoRoot 'CHANGELOG.md'
$versionPattern = '(?m)^\.VERSION\s+(?<major>\d+)\.(?<minor>\d+)\.(?<date>\d{8})(?:\.(?<counter>\d+))?\s*$'
$utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)

function Get-VersionMatch {
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

if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
    throw "Versioned script not found: $scriptPath"
}

$scriptContent = [System.IO.File]::ReadAllText($scriptPath)
$workingVersion = Get-VersionMatch -Content $scriptContent -Source $scriptPath

$date = Get-Date -Format 'yyyyMMdd'
$counter = 1
$parentRevisions = @('HEAD')
$mergeHeadPath = Join-Path $repoRoot '.git\MERGE_HEAD'
if (Test-Path -LiteralPath $mergeHeadPath -PathType Leaf) {
    $parentRevisions += [System.IO.File]::ReadAllLines($mergeHeadPath)
}

foreach ($revision in $parentRevisions) {
    $parentContent = & git -C $repoRoot show "${revision}:azKerberosRollover.ps1" 2>$null
    if ($LASTEXITCODE -ne 0) {
        continue
    }

    $parentVersion = Get-VersionMatch -Content ($parentContent -join "`n") -Source "${revision}:azKerberosRollover.ps1"
    if ($parentVersion.Groups['date'].Value -eq $date -and $parentVersion.Groups['counter'].Success) {
        $counter = [Math]::Max($counter, [int]$parentVersion.Groups['counter'].Value + 1)
    }
}

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

$stagedChanges = & git -C $repoRoot diff --cached --name-status --diff-filter=ACDMRTUXB
if ($LASTEXITCODE -ne 0) {
    throw 'Could not read the staged changes.'
}

$changeDescriptions = foreach ($change in $stagedChanges) {
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

$escapedVersion = [regex]::Escape($version)
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

[System.IO.File]::WriteAllText($scriptPath, $scriptContent, $utf8WithoutBom)
[System.IO.File]::WriteAllText($changelogPath, $changelogContent, $utf8WithoutBom)

& git -C $repoRoot add -- $scriptPath $changelogPath
if ($LASTEXITCODE -ne 0) {
    throw 'Could not stage the updated version and changelog.'
}

Write-Host "Prepared version $version."
