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
    param(
        [Parameter(Mandatory = $true)]
        [string]$Revision
    )

    & git cat-file -e "$Revision`^{commit}" 2>$null
    return $LASTEXITCODE -eq 0
}

if (-not (Test-GitRevision -Revision $HeadRevision)) {
    throw "Head revision '$HeadRevision' is unavailable."
}

$zeroRevisionPattern = '^0+$'
if ($BaseRevision -match $zeroRevisionPattern -or -not (Test-GitRevision -Revision $BaseRevision)) {
    $remoteDefaultBranch = "origin/$DefaultBranch"
    if (-not (Test-GitRevision -Revision $remoteDefaultBranch)) {
        throw "Neither base revision '$BaseRevision' nor '$remoteDefaultBranch' is available."
    }

    $BaseRevision = (Invoke-Git -Arguments @('merge-base', $remoteDefaultBranch, $HeadRevision))[0]
}

$commits = @(
    Invoke-Git -Arguments @('rev-list', '--reverse', "$BaseRevision..$HeadRevision")
)

if ($commits.Count -eq 0) {
    Write-Host 'No new commits require changelog validation.'
    exit 0
}

$failures = [System.Collections.Generic.List[string]]::new()
$versionPattern = '(?m)^\.VERSION\s+(?<version>\d+\.\d+\.\d{8}\.\d+)\s*$'

foreach ($commit in $commits) {
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
    $entryPattern = "(?m)^## \[$([regex]::Escape($version))\] - \d{4}-\d{2}-\d{2}\s*$"
    if (-not [regex]::IsMatch($changelogContent, $entryPattern)) {
        $failures.Add("$commit updates CHANGELOG.md but has no entry for version $version.")
        continue
    }

    Write-Host "Validated $commit with changelog version $version."
}

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Error $_ -ErrorAction Continue }
    throw "Changelog validation failed for $($failures.Count) commit(s). Enable the repository Git hooks and recreate the affected commits."
}

Write-Host "Validated changelog updates for $($commits.Count) commit(s)."
