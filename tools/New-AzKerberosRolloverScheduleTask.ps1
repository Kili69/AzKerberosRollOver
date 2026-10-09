#Requires -Version 5.1

<#
.SYNOPSIS
    Creates or updates the AzKerberosRollOver scheduled task.
.DESCRIPTION
    Registers a scheduled task named AzKerberosRollOver that runs
    azKerberosRollover.ps1 as local SYSTEM with highest privileges.

    Missing account, time, recurrence, path, and log path parameters are requested
    interactively. Press Enter to accept the displayed default. A blank LogPath
    lets azKerberosRollover.ps1 use its default log directory.
.PARAMETER KerberosRollOverAccount
    Active Directory rollover account passed to RollOverADAccountName. The default
    is svc-KerberosRollOver. The account can be specified as sAMAccountName, UPN, or
    DOMAIN\sAMAccountName and must exist in Active Directory.
.PARAMETER TimeToRun
    Start time in 24-hour HH:mm format. The default is 01:00.
.PARAMETER Repeat
    Recurrence interval: Daily, Weekly, or Hourly. Weekly uses the current weekday.
    Hourly starts at the next occurrence of TimeToRun and then repeats every hour.
.PARAMETER Path
    Directory containing azKerberosRollover.ps1, or the full path to that script.
    The default is the current directory. When the current directory is named tools,
    its parent directory is used because azKerberosRollover.ps1 is stored there.
.PARAMETER LogPath
    Existing directory passed to azKerberosRollover.ps1 as LogPath. Leave blank to
    use the rollover script's default log directory.
.PARAMETER Force
    Replaces an existing task without a confirmation prompt. This parameter does not
    override WhatIf.
.EXAMPLE
    .\tools\New-AzKerberosRolloverScheduleTask.ps1

    Interactively requests all task settings and displays the documented defaults.
.EXAMPLE
    .\tools\New-AzKerberosRolloverScheduleTask.ps1 `
        -KerberosRollOverAccount 'Svc-KerberosRollOver@contoso.com' `
        -TimeToRun '01:00' `
        -Repeat Daily `
        -Path 'C:\Program Files\AzKerberosRollOver' `
        -LogPath 'C:\ProgramData\AzKerberosRollOver\Logs' `
        -Force

    Creates the daily SYSTEM task, or updates its parameters when it already exists,
    without confirmation.
.EXAMPLE
    .\tools\New-AzKerberosRolloverScheduleTask.ps1 `
        -KerberosRollOverAccount 'CONTOSO\Svc-KerberosRollOver' `
        -TimeToRun '06:00' `
        -Repeat Weekly `
        -Path 'C:\Program Files\AzKerberosRollOver' `
        -WhatIf

    Previews a weekly task on the current weekday without changing Task Scheduler.
.NOTES
    Run this script from an elevated Windows PowerShell session when creating or
    updating the scheduled task.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param (
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$KerberosRollOverAccount = 'svc-KerberosRollOver',

    [Parameter()]
    [string]$TimeToRun = '01:00',

    [Parameter()]
    [string]$Repeat = 'Daily',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Path = (Get-Location).Path,

    [Parameter()]
    [AllowEmptyString()]
    [string]$LogPath,

    [switch]$Force
)

<#
.SYNOPSIS
    Reads an interactive value while displaying and preserving a default.
.DESCRIPTION
    Displays the supplied prompt and default through Read-Host. Empty or whitespace
    input returns the default; nonempty input is trimmed before it is returned.
    An empty default is displayed as "use script default" for LogPath.
.OUTPUTS
    System.String
#>
function Read-ValueWithDefault {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Prompt,
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Default
    )

    $displayDefault = if ([string]::IsNullOrWhiteSpace($Default)) {
        'use script default'
    }
    else {
        $Default
    }
    $value = Read-Host "$Prompt [$displayDefault]"
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $Default
    }
    return $value.Trim()
}

<#
.SYNOPSIS
    Quotes one value for the Windows PowerShell scheduled-task command line.
.DESCRIPTION
    Wraps paths and account names in double quotes so embedded spaces remain part of
    one argument. Values containing a double quote are rejected instead of attempting
    ambiguous command-line escaping.
.OUTPUTS
    System.String
#>
function ConvertTo-QuotedTaskArgument {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    if ($Value.Contains('"')) {
        throw [System.ArgumentException] "Task arguments cannot contain a double quote: $Value"
    }
    return '"{0}"' -f $Value
}

<#
.SYNOPSIS
    Resolves the installed azKerberosRollover.ps1 file.
.DESCRIPTION
    Accepts either a directory or a full script path. Directory input is expanded to
    azKerberosRollover.ps1. The function rejects nonexistent paths, other file names,
    and directories that do not contain the expected script. When the script exists
    one level above the selected directory, the error suggests that parent path.
.OUTPUTS
    System.String containing the absolute script path.
#>
function Resolve-RolloverScriptPath {
    param (
        [Parameter(Mandatory = $true)]
        [string]$InputPath
    )

    # LiteralPath prevents wildcard characters in a filesystem path from being
    # interpreted as a pattern.
    if (!(Test-Path -LiteralPath $InputPath)) {
        throw [System.IO.DirectoryNotFoundException] "The specified path does not exist: $InputPath. Enter the directory containing azKerberosRollover.ps1 or the full path to the script."
    }

    $resolvedPath = Resolve-Path -LiteralPath $InputPath -ErrorAction Stop
    $pathItem = Get-Item -LiteralPath $resolvedPath -ErrorAction Stop
    # Normalize both accepted input shapes to one concrete script file.
    if ($pathItem.PSIsContainer) {
        $scriptPath = Join-Path $resolvedPath.Path 'azKerberosRollover.ps1'
    }
    else {
        $scriptPath = $resolvedPath.Path
    }

    if ([System.IO.Path]::GetFileName($scriptPath) -ine 'azKerberosRollover.ps1') {
        throw [System.ArgumentException] "The selected file is not azKerberosRollover.ps1: $scriptPath. Enter the directory containing azKerberosRollover.ps1 or the full path to the script."
    }
    if (!(Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        $message = "azKerberosRollover.ps1 was not found in the selected directory: $($resolvedPath.Path)."
        $parentPath = Split-Path -Path $resolvedPath.Path -Parent
        if ($parentPath -and (Test-Path -LiteralPath (Join-Path $parentPath 'azKerberosRollover.ps1') -PathType Leaf)) {
            $message += " The script was found in the parent directory: $parentPath. Enter '..' or that full directory path."
        }
        else {
            $message += ' Enter the directory containing azKerberosRollover.ps1 or the full path to the script.'
        }
        throw [System.IO.FileNotFoundException] $message
    }

    return (Resolve-Path -LiteralPath $scriptPath -ErrorAction Stop).Path
}

<#
.SYNOPSIS
    Resolves and validates the Active Directory rollover account.
.DESCRIPTION
    Accepts a sAMAccountName, UPN, or DOMAIN\sAMAccountName. A plain name is searched
    on the current domain PDC, a domain-qualified name on that domain's PDC, and a UPN
    through a Global Catalog. Exactly one matching user must exist.
.OUTPUTS
    Microsoft.ActiveDirectory.Management.ADUser
#>
function Resolve-KerberosRolloverAccount {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Identity
    )

    # Default to the current domain for an unqualified sAMAccountName.
    $lookupValue = $Identity
    $lookupProperty = 'SamAccountName'
    $searchServer = (Get-ADDomain -ErrorAction Stop).PDCEmulator

    # Regex: ^ and $ anchor the complete value; (?<Domain>[^\\]+) captures one or
    # more non-backslash characters as Domain; \\ matches the literal separator;
    # (?<Name>[^\\]+) captures the remaining non-backslash characters as Name.
    if ($Identity -match '^(?<Domain>[^\\]+)\\(?<Name>[^\\]+)$') {
        try {
            $domain = Get-ADDomain -Identity $Matches.Domain -ErrorAction Stop
        }
        catch {
            if ($_.Exception.GetType().FullName -eq 'Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException') {
                throw [System.Management.Automation.ItemNotFoundException] "The Kerberos rollover account '$Identity' was not found in Active Directory. Enter an existing sAMAccountName, UPN, or DOMAIN\sAMAccountName."
            }
            throw
        }
        $searchServer = $domain.PDCEmulator
        $lookupValue = $Matches.Name
    }
    elseif ($Identity -like '*@*') {
        # -like uses wildcard matching, not regex. An at sign identifies UPN input,
        # whose owning domain must first be discovered through the Global Catalog.
        $globalCatalog = Get-ADDomainController `
            -Discover `
            -Service GlobalCatalog `
            -ErrorAction Stop
        $searchServer = '{0}:3268' -f $globalCatalog.HostName.Value
        $lookupProperty = 'UserPrincipalName'
    }

    # Use AD filter script blocks so the directory performs the lookup server-side.
    if ($lookupProperty -eq 'UserPrincipalName') {
        $users = @(
            Get-ADUser `
                -Filter {UserPrincipalName -eq $lookupValue} `
                -Server $searchServer `
                -ErrorAction Stop
        )
    }
    else {
        $users = @(
            Get-ADUser `
                -Filter {SamAccountName -eq $lookupValue} `
                -Server $searchServer `
                -ErrorAction Stop
        )
    }

    if ($users.Count -eq 0) {
        throw [System.Management.Automation.ItemNotFoundException] "The Kerberos rollover account '$Identity' was not found in Active Directory. Enter an existing sAMAccountName, UPN, or DOMAIN\sAMAccountName."
    }
    if ($users.Count -gt 1) {
        throw [System.InvalidOperationException] "More than one Active Directory account matched '$Identity'. Enter a unique UPN or DOMAIN\sAMAccountName."
    }

    return $users[0]
}

<#
.SYNOPSIS
    Resolves and validates the optional log directory.
.DESCRIPTION
    Returns an empty string unchanged so azKerberosRollover.ps1 can select its default
    location. A nonempty value must exist and must resolve to a directory rather than
    a file.
.OUTPUTS
    System.String containing an absolute directory path, or an empty string.
#>
function Resolve-LogDirectory {
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$InputPath
    )

    if ([string]::IsNullOrWhiteSpace($InputPath)) {
        return ''
    }
    if (!(Test-Path -LiteralPath $InputPath)) {
        throw [System.IO.DirectoryNotFoundException] "The specified log directory does not exist: $InputPath. Enter an existing directory or leave the value blank to use the rollover script's default log directory."
    }

    $resolvedPath = Resolve-Path -LiteralPath $InputPath -ErrorAction Stop
    if (!(Get-Item -LiteralPath $resolvedPath -ErrorAction Stop).PSIsContainer) {
        throw [System.ArgumentException] "LogPath must identify a directory, but a file was supplied: $($resolvedPath.Path). Enter an existing directory or leave the value blank."
    }

    return $resolvedPath.Path
}

$ScriptVersion = '0.1.20261009.11'
$TaskName = 'AzKerberosRollOver'
$TaskPath = '\'
$MicrosoftRolloverDocumentation = 'https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sso-faq#how-can-i-roll-over-the-kerberos-decryption-key-of-the-azureadsso-computer-account'
# Regex: ^ and $ anchor the entire value. (?:...) is a noncapturing choice between
# an optional-leading-zero hour from 0 through 19 ([01]?\d) and an hour from 20
# through 23 (2[0-3]). The literal colon separates the hour from minutes, and
# [0-5]\d accepts minutes from 00 through 59.
$ValidTimePattern = '^(?:[01]?\d|2[0-3]):[0-5]\d$'

Write-Information "AzKerberosRollOver scheduled task setup - Version $ScriptVersion" -InformationAction Continue

# Import explicitly with verbose disabled so -Verbose produces concise script
# diagnostics rather than one message for every exported module command.
if (!(Get-Module -Name ScheduledTasks)) {
    Import-Module ScheduledTasks -ErrorAction Stop -Verbose:$false
    Write-Verbose 'Imported ScheduledTasks module'
}
else {
    Write-Verbose 'ScheduledTasks module is already imported'
}

if (!(Get-Module -Name ActiveDirectory)) {
    Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false
    Write-Verbose 'Imported ActiveDirectory module'
}
else {
    Write-Verbose 'ActiveDirectory module is already imported'
}

# Bound-parameter tracking distinguishes automation input, which must fail fast, from
# interactive input, which should explain validation failures and prompt again.
$accountWasProvided = $PSBoundParameters.ContainsKey('KerberosRollOverAccount')
if (!$accountWasProvided) {
    while ($true) {
        $KerberosRollOverAccount = Read-ValueWithDefault `
            -Prompt 'Kerberos rollover account' `
            -Default $KerberosRollOverAccount
        try {
            $resolvedRolloverAccount = Resolve-KerberosRolloverAccount `
                -Identity $KerberosRollOverAccount
            break
        }
        # Only a genuine "not found" result is retryable. Duplicate identities,
        # connectivity problems, and permission errors remain terminating failures.
        catch [System.Management.Automation.ItemNotFoundException] {
            Write-Warning $_.Exception.Message
        }
    }
}
else {
    $resolvedRolloverAccount = Resolve-KerberosRolloverAccount `
        -Identity $KerberosRollOverAccount
}
Write-Verbose "Resolved Kerberos rollover account to $($resolvedRolloverAccount.DistinguishedName)"

$timeWasProvided = $PSBoundParameters.ContainsKey('TimeToRun')
if (!$timeWasProvided) {
    while ($true) {
        $TimeToRun = Read-ValueWithDefault `
            -Prompt 'Time to run (HH:mm)' `
            -Default $TimeToRun
        # The regex stored in ValidTimePattern is explained where it is declared.
        if ($TimeToRun -match $ValidTimePattern) {
            break
        }
        Write-Warning "The time '$TimeToRun' is invalid. Enter a valid 24-hour time between 00:00 and 23:59 in HH:mm format."
    }
}
elseif ($TimeToRun -notmatch $ValidTimePattern) {
    throw [System.ArgumentException] "TimeToRun '$TimeToRun' is invalid. Enter a valid 24-hour time between 00:00 and 23:59 in HH:mm format."
}
$repeatWasProvided = $PSBoundParameters.ContainsKey('Repeat')
if (!$repeatWasProvided) {
    # Validate inside the loop rather than through ValidateSet so an interactive typo
    # can be corrected without terminating parameter-binding metadata errors.
    while ($true) {
        $Repeat = Read-ValueWithDefault `
            -Prompt 'Repeat (Daily, Weekly, or Hourly)' `
            -Default $Repeat
        if ($Repeat -in @('Daily', 'Weekly', 'Hourly')) {
            break
        }
        Write-Warning "The repeat value '$Repeat' is invalid. Enter Daily, Weekly, or Hourly."
    }
}
elseif ($Repeat -notin @('Daily', 'Weekly', 'Hourly')) {
    throw [System.ArgumentException] "Repeat '$Repeat' is invalid. Enter Daily, Weekly, or Hourly."
}
$pathWasProvided = $PSBoundParameters.ContainsKey('Path')
if (!$pathWasProvided) {
    $currentPath = (Get-Location).Path
    # The tool is installed below the main script. When launched from tools, propose
    # its parent so pressing Enter resolves azKerberosRollover.ps1 immediately.
    if ((Split-Path -Path $currentPath -Leaf) -ieq 'tools') {
        $Path = Split-Path -Path $currentPath -Parent
    }
    else {
        $Path = $currentPath
    }

    # Interactive path failures remain correctable; an explicitly bound Path is
    # resolved once below and its validation error terminates the script.
    while ($true) {
        $Path = Read-ValueWithDefault `
            -Prompt 'Directory containing azKerberosRollover.ps1, or full script path' `
            -Default $Path
        try {
            $rolloverScriptPath = Resolve-RolloverScriptPath -InputPath $Path
            break
        }
        catch {
            Write-Warning $_.Exception.Message
        }
    }
}
$logPathWasProvided = $PSBoundParameters.ContainsKey('LogPath')
if (!$logPathWasProvided) {
    # Keep an empty default on every retry so users can fall back to the rollover
    # script's own log location even after entering an invalid directory.
    while ($true) {
        $logPathInput = Read-ValueWithDefault -Prompt 'Log directory' -Default ''
        try {
            $LogPath = Resolve-LogDirectory -InputPath $logPathInput
            break
        }
        catch {
            Write-Warning $_.Exception.Message
        }
    }
}

# Parameter-supplied paths fail fast instead of entering an interactive loop.
if ($pathWasProvided) {
    $rolloverScriptPath = Resolve-RolloverScriptPath -InputPath $Path
}

if ($logPathWasProvided) {
    $LogPath = Resolve-LogDirectory -InputPath $LogPath
}

# TimeToRun has already passed the documented regex, so both array elements are safe
# integer hour/minute values for a trigger anchored to today.
$timeParts = $TimeToRun.Split(':')
$triggerTime = [DateTime]::Today.AddHours([int]$timeParts[0]).AddMinutes([int]$timeParts[1])

switch ($Repeat) {
    'Daily' {
        $trigger = New-ScheduledTaskTrigger -Daily -At $triggerTime
        $scheduleDescription = "daily at $($triggerTime.ToString('HH:mm'))"
    }
    'Weekly' {
        # No separate weekday parameter is required: weekly tasks use the weekday on
        # which this setup command is executed.
        $dayOfWeek = (Get-Date).DayOfWeek
        $trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek $dayOfWeek -At $triggerTime
        $scheduleDescription = "weekly on $dayOfWeek at $($triggerTime.ToString('HH:mm'))"
    }
    'Hourly' {
        # An hourly trigger is anchored to the next occurrence of TimeToRun and then
        # repeats indefinitely at one-hour intervals.
        $firstRun = $triggerTime
        if ($firstRun -le (Get-Date)) {
            $firstRun = $firstRun.AddDays(1)
        }
        $trigger = New-ScheduledTaskTrigger `
            -Once `
            -At $firstRun `
            -RepetitionInterval (New-TimeSpan -Hours 1)
        $scheduleDescription = "hourly starting at $($firstRun.ToString('yyyy-MM-dd HH:mm'))"
    }
}

# Use Windows PowerShell explicitly because the AzureADSSO module is a Windows
# PowerShell module installed with Microsoft Entra Connect.
$powerShellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

# Build one noninteractive command line. Dynamic values are individually quoted by a
# helper that rejects embedded quotes, preventing malformed argument boundaries.
$taskArguments = @(
    '-NoProfile'
    '-NonInteractive'
    '-ExecutionPolicy'
    'Bypass'
    '-File'
    (ConvertTo-QuotedTaskArgument -Value $rolloverScriptPath)
    '-RollOverADAccountName'
    (ConvertTo-QuotedTaskArgument -Value $KerberosRollOverAccount)
)
if (![string]::IsNullOrWhiteSpace($LogPath)) {
    $taskArguments += '-LogPath'
    $taskArguments += ConvertTo-QuotedTaskArgument -Value $LogPath
}
if ($VerbosePreference -eq 'Continue') {
    # Verbose setup also opts the future rollover executions into verbose file and
    # console diagnostics.
    $taskArguments += '-Verbose'
}

# SYSTEM removes the need to store task credentials. Highest privileges are required
# for event-source creation and the configured AD operations.
$action = New-ScheduledTaskAction `
    -Execute $powerShellPath `
    -Argument ($taskArguments -join ' ')
$principal = New-ScheduledTaskPrincipal `
    -UserId 'SYSTEM' `
    -LogonType ServiceAccount `
    -RunLevel Highest
# Start missed runs when possible, reject overlapping instances, and terminate a
# stalled rollover after one hour.
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Hours 1)
# Keep operational context in Task Scheduler so administrators can identify the
# purpose, identity, executable path, cadence, and authoritative documentation.
$description = @"
AzKerberosRollOver resets the synchronized rollover account password, verifies that the new credential is available in Microsoft Entra ID, and updates the seamless SSO Kerberos key in AzureADSSOAcc.
Rollover account: $KerberosRollOverAccount
Script path: $rolloverScriptPath
Schedule: $scheduleDescription
Microsoft documentation: $MicrosoftRolloverDocumentation
"@

Write-Verbose "Task name: $TaskName"
Write-Verbose "Schedule: $scheduleDescription"
Write-Verbose "Program: $powerShellPath"
Write-Verbose "Arguments: $($taskArguments -join ' ')"
Write-Verbose "Description: $description"

# Restrict detection to the root Task Scheduler folder so a same-named task in
# another folder is not modified accidentally.
$existingTask = Get-ScheduledTask `
    -TaskName $TaskName `
    -TaskPath $TaskPath `
    -ErrorAction SilentlyContinue
$taskOperation = if ($existingTask) {
    'Update scheduled task parameters'
}
else {
    'Create scheduled task'
}
Write-Verbose "Operation: $taskOperation"

# Force bypasses the high-impact confirmation but never overrides WhatIf.
$applyChange = $Force -and !$WhatIfPreference
if (!$applyChange) {
    $applyChange = $PSCmdlet.ShouldProcess(
        "$TaskName ($scheduleDescription)",
        "$taskOperation for local SYSTEM"
    )
}
if (!$applyChange) {
    return
}

# Defer the elevation check until after ShouldProcess so any user can run -WhatIf
# without administrator rights.
$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principalContext = New-Object System.Security.Principal.WindowsPrincipal($currentIdentity)
if (!$principalContext.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw [System.UnauthorizedAccessException] 'Run this script from an elevated Windows PowerShell session.'
}

if ($existingTask) {
    # Description is not exposed as a named Set-ScheduledTask parameter. Updating the
    # writable CIM task object lets one operation persist description and definition.
    $existingTask.Description = $description
    $existingTask.Actions = @($action)
    $existingTask.Triggers = @($trigger)
    $existingTask.Principal = $principal
    $existingTask.Settings = $settings

    Set-ScheduledTask `
        -InputObject $existingTask `
        -ErrorAction Stop | Out-Null
    $resultAction = 'updated'
}
else {
    # Register only when the root task does not exist; subsequent executions use the
    # update path above and preserve the task identity.
    Register-ScheduledTask `
        -TaskName $TaskName `
        -TaskPath $TaskPath `
        -Description $description `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -ErrorAction Stop | Out-Null
    $resultAction = 'created'
}

Write-Information "Scheduled task $TaskName was $resultAction successfully and will run $scheduleDescription." -InformationAction Continue
