<#PSScriptInfo

.VERSION 1.1.20261009.1
.GUID 2efdf5d8-370e-425c-afad-e5951a84f893

.AUTHOR Andreas Lucas [MSFT]

.COPYRIGHT
Copyright (c) 2021-2026 Andreas Lucas. Licensed under the MIT License.

.TAGS
Azure, Active Directory, Kerberos, RollOver, Hybrid
.LICENSEURI

.PROJECTURI
https://github.com/Kili69/AzKerberosRollOver

.DESCRIPTION
Rolls over the Microsoft Entra seamless SSO Kerberos decryption key.

.ICONURI

.EXTERNALMODULEDEPENDENCIES

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES
AzureADSSO Module, ActiveDirectory Module

.RELEASENOTES

#>

<#
.SYNOPSIS
    Rolls over the Microsoft Entra seamless SSO Kerberos decryption key.
.DESCRIPTION
    Resets the password of a synchronized Active Directory rollover account and uses
    that identity to update the AzureADSSOAcc computer account through the AzureADSSO
    module.

    Run this script from a Microsoft Entra Connect server in Windows PowerShell with
    permission to create an Application event source, reset the rollover account, read
    Active Directory through the Global Catalog and PDC emulator, and update seamless SSO.

    The generated password is held in process memory only and is never written to the
    debug log.

    The script performs the following operations:
    1. Imports the AzureADSSO and ActiveDirectory modules, plus ADSync when requested.
    2. Validates the configured timing values, rollover account, and AD permissions.
    3. Locates AzureADSSOAcc through a Global Catalog and checks its pwdLastSet value.
    4. Stops when the previous rollover is still within the configured TGT lifetime,
       unless IgnoreTGTLifetimeCheck is specified.
    5. Enables the rollover account and resets it with a new generated password.
    6. Optionally starts an Entra Connect delta synchronization and checks every
       30 seconds for up to five minutes whether Microsoft Entra authentication
       succeeds with the new password.
    7. Runs the AzureADSSO forest update in a SYSTEM background job with explicit
       cloud and on-premises credentials for the rollover account.
    8. Reads pwdLastSet from the PDC emulator to verify that the update succeeded.
    9. Disables the rollover account before the script exits, including after errors.

    Return codes:
    0x0    Success
    0x3EA  The Windows event source could not be created.
    0x3EB  Microsoft Entra authentication with the new password could not be verified.
    0x3EC  Microsoft Entra authentication was blocked by MFA or Conditional Access.
    0x1    The rollover workflow terminated with another error.
.PARAMETER AzureADSSOModule
    Full path to AzureADSSO.psd1. The default is the standard Microsoft Entra Connect
    installation path under Program Files.
.PARAMETER RollOverADAccountName
    Active Directory account used for the rollover. The value can be supplied as a
    sAMAccountName, user principal name (UPN), or DOMAIN\sAMAccountName. The account
    must be synchronized to Microsoft Entra ID. The default is AzKrbRollOver.
.PARAMETER RollOverAccountUPN
    Microsoft Entra UPN of the rollover account. When omitted, the value is read from
    the matching Active Directory user.
.PARAMETER LogPath
    Directory in which the debug log is written. A file path is reduced to its parent
    directory. Missing or invalid paths fall back to the current user's LOCALAPPDATA.
.PARAMETER StartEntraConnectSync
    Starts an Entra Connect delta synchronization after resetting the rollover account
    password. By default, no synchronization is started. Leave this switch unset when
    synchronization is handled separately, for example by Microsoft Entra Cloud Sync.
.PARAMETER TGTLifetimeHours
    Minimum age, in hours, of the current AzureADSSOAcc password before another
    rollover is allowed. Values are constrained to 0 through 24 hours. A value of 0
    allows an immediate rollover. The default is 10 hours.
.PARAMETER IgnoreTGTLifetimeCheck
    Bypasses the TGT lifetime safety check and forces the rollover workflow to proceed.
.PARAMETER Verbose
    Displays detailed progress and diagnostic messages in the console. Diagnostic
    messages continue to be written to the log file regardless of this setting.
.PARAMETER WhatIf
    Validates prerequisites and reports the planned rollover without changing
    passwords, starting synchronization, updating seamless SSO, or writing logs.
.EXAMPLE
    .\azKerberosRollover.ps1 -RollOverAccountUPN 'AzKrbRollOver@contoso.com'

    Performs a rollover with the default account name, timing values, and log location.
.EXAMPLE
    .\azKerberosRollover.ps1 -RollOverADAccountName 'SvcKrbRollover' `
        -RollOverAccountUPN 'SvcKrbRollover@contoso.com' `
        -StartEntraConnectSync -LogPath 'C:\Logs'

    Uses a custom rollover account, starts an Entra Connect delta synchronization,
    and writes the debug log under C:\Logs.
.EXAMPLE
    .\azKerberosRollover.ps1 -RollOverADAccountName 'SvcKrbRollover@contoso.com'

    Resolves the rollover account by its Active Directory user principal name.
.EXAMPLE
    .\azKerberosRollover.ps1 -RollOverADAccountName 'CONTOSO\SvcKrbRollover'

    Resolves the rollover account by its NetBIOS domain and sAMAccountName.
.EXAMPLE
    .\azKerberosRollover.ps1 -StartEntraConnectSync -IgnoreTGTLifetimeCheck

    Starts an Entra Connect delta synchronization and forces the rollover regardless
    of the previous AzureADSSOAcc password age.
.EXAMPLE
    .\azKerberosRollover.ps1 -RollOverAccountUPN 'AzKrbRollOver@contoso.com' -Verbose

    Performs a rollover and displays detailed progress and diagnostic messages.
.EXAMPLE
    .\azKerberosRollover.ps1 -RollOverAccountUPN 'AzKrbRollOver@contoso.com' -WhatIf

    Validates the environment and reports the planned rollover without making changes.
.NOTES
    https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sso-faq#how-can-i-roll-over-the-kerberos-decryption-key-of-the-%60azureadsso%60-computer-account
.LINK
    https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sso-faq
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory=$false)]
    [string]$AzureADSSOModule = "$env:ProgramFiles\Microsoft Azure Active Directory Connect\AzureADSSO.psd1",
    [Parameter(Mandatory=$false)]
    [string]$RollOverADAccountName = "AzKrbRollOver",
    [Parameter(Mandatory=$false)]
    [string]$RollOverAccountUPN,
    [Parameter(Mandatory=$false)]
    [string]$LogPath,
    [switch]$StartEntraConnectSync,
    [Parameter (Mandatory=$false)]
    [int]$TGTLifetimeHours = 10,
    [switch]$IgnoreTGTLifetimeCheck
)

# Capture the common-parameter state once so helper functions and background-safe
# logging decisions use the same WhatIf value throughout the run.
$script:IsWhatIf = [bool]$WhatIfPreference

<#
.SYNOPSIS
    Generates a password from the character set accepted by the rollover workflow.
.DESCRIPTION
    Selects each character independently with Get-Random from uppercase letters,
    lowercase letters, digits, and the supported punctuation characters.
.PARAMETER Length
    Number of characters to generate. The default is 14. The main workflow requests
    a 32-character password.
.EXAMPLE
    New-RandomPassword -Length 32

    Generates the password length used by the rollover workflow.
.EXAMPLE
    New-RandomPassword

    Generates a 14-character password.
.OUTPUTS
    System.String
#>
function New-RandomPassword {
    param (
        [int]$length = 14
    )

    $chars = @()
    $chars += [char[]](65..90)  # Uppercase A-Z
    $chars += [char[]](97..122) # Lowercase a-z
    $chars += [char[]](48..57)  # Numbers 0-9
    $chars += [char[]](33)      # Exclamation mark
    $chars += [char[]](35..38)  # Number sign, dollar, percent, ampersand
    $chars += [char[]](40..47)  # Parentheses, asterisk, plus, comma, hyphen, period, slash

    # Sampling each position independently avoids predictable character placement.
    $password = -join ((1..$length) | ForEach-Object { $chars | Get-Random })
    return $password
}
<#
.SYNOPSIS
    Tests whether security principals have an Active Directory right.
.DESCRIPTION
    Evaluates direct and inherited allow and deny access rules for the supplied
    principal SIDs. GenericAll satisfies every requested right, and an unscoped
    access rule satisfies a request for a specific object type.
.PARAMETER DistinguishedName
    Distinguished name of the Active Directory object whose ACL is evaluated.
.PARAMETER PrincipalSids
    SID values for the principal and its transitive security groups.
.PARAMETER RequiredRight
    Active Directory right to test.
.PARAMETER ObjectType
    Optional GUID of the extended right, property, or property set.
.OUTPUTS
    System.Boolean
#>
function Test-ADObjectRight {
    param (
        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName,
        [Parameter(Mandatory = $true)]
        [string[]]$PrincipalSids,
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.ActiveDirectoryRights]$RequiredRight,
        [Guid]$ObjectType = [Guid]::Empty
    )

    # The AD provider returns both explicit and inherited ACEs. SID output avoids
    # account-name translation differences between domains.
    $acl = Get-Acl -Path "AD:\$DistinguishedName" -ErrorAction Stop
    $rules = $acl.GetAccessRules(
        $true,
        $true,
        [System.Security.Principal.SecurityIdentifier]
    )
    $isAllowed = $false

    foreach ($rule in $rules) {
        if ($rule.IdentityReference.Value -notin $PrincipalSids) {
            continue
        }

        # GenericAll covers every requested operation. Otherwise, the ACE must carry
        # the requested right and be unscoped or scoped to the requested object GUID.
        $hasGenericAll = (
            $rule.ActiveDirectoryRights -band
            [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
        ) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
        $hasRequiredRight = (
            $rule.ActiveDirectoryRights -band
            $RequiredRight
        ) -eq $RequiredRight
        $coversRequestedRight = $hasGenericAll -or (
            $hasRequiredRight -and
            ($rule.ObjectType -eq [Guid]::Empty -or $rule.ObjectType -eq $ObjectType)
        )

        if (!$coversRequestedRight) {
            continue
        }
        # A matching deny takes precedence over allow and therefore fails immediately.
        if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
            return $false
        }

        $isAllowed = $true
    }

    return $isAllowed
}
<#
.SYNOPSIS
    Classifies a Microsoft Entra authentication failure.
.DESCRIPTION
    Uses documented AADSTS error codes when available. Generic WS-Trust
    Authentication Failure responses are treated as retryable credential failures
    because they do not identify Conditional Access or MFA as the cause.
.PARAMETER Message
    Authentication error text returned by Microsoft Entra or WS-Trust.
.OUTPUTS
    System.String
#>
function Get-EntraAuthenticationFailureCategory {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    # Regex: AADSTS is literal; (?:...) is a noncapturing alternation of known MFA
    # and Conditional Access codes; \b requires a word boundary after the code so a
    # longer unrelated number cannot match by prefix.
    # Regex: (?i) enables case-insensitive matching for the literal provider marker.
    if ($Message -match 'AADSTS(?:50072|50074|50076|50078|50079|53000|53001|53002|53003|53004|530035|53010|53011|530032)\b' -or
        $Message -match '(?i)BlockedByConditionalAccess') {
        return 'AuthenticationPolicyBlocked'
    }
    # Regex: AADSTS50126 is the invalid-credentials code and \b terminates the exact
    # code. In the second pattern, (?i) is case-insensitive, | separates alternatives,
    # (?:...) groups alternatives without capturing, and the optional space in
    # "user ?name" accepts both "username" and "user name".
    if ($Message -match 'AADSTS50126\b' -or
        $Message -match '(?i)Authentication Failure|invalid (?:user ?name|password|credentials)') {
        return 'InvalidCredentials'
    }

    return 'Unknown'
}
<#
.SYNOPSIS
    Extracts actionable diagnostics from a PowerShell background job.
.DESCRIPTION
    Combines errors returned by Receive-Job, errors retained by the child job,
    the job-state exception, nested exception messages, ErrorDetails, and the
    fully qualified error identifier into one deduplicated message.
.PARAMETER ErrorRecords
    Error records captured while receiving job output.
.PARAMETER Job
    The background job whose retained errors and failure reason are inspected.
.OUTPUTS
    System.String
#>
function Get-BackgroundJobErrorMessage {
    param (
        [System.Collections.IEnumerable]$ErrorRecords,
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Job]$Job
    )

    $messages = [System.Collections.Generic.List[string]]::new()
    $records = @()
    if ($ErrorRecords) {
        $records += @($ErrorRecords)
    }
    foreach ($childJob in $Job.ChildJobs) {
        $records += @($childJob.Error)
    }

    foreach ($record in $records) {
        if ($record -is [System.Management.Automation.ErrorRecord]) {
            if ($record.ErrorDetails -and $record.ErrorDetails.Message) {
                [void]$messages.Add($record.ErrorDetails.Message)
            }
            if ($record.Exception) {
                $exception = $record.Exception
                while ($exception) {
                    if ($exception.Message) {
                        [void]$messages.Add($exception.Message)
                    }
                    $exception = $exception.InnerException
                }
            }
            if ($record.FullyQualifiedErrorId) {
                [void]$messages.Add("Error ID: $($record.FullyQualifiedErrorId)")
            }
        }

        $recordText = $record.ToString()
        if ($recordText) {
            [void]$messages.Add($recordText)
        }
    }

    foreach ($childJob in $Job.ChildJobs) {
        $reason = $childJob.JobStateInfo.Reason
        while ($reason) {
            if ($reason.Message) {
                [void]$messages.Add($reason.Message)
            }
            $reason = $reason.InnerException
        }
    }

    $uniqueMessages = @(
        $messages |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
    )
    if ($uniqueMessages.Count -eq 0) {
        return "The background job returned no diagnostic details (state: $($Job.State))"
    }

    return $uniqueMessages -join ' | '
}
<#
.SYNOPSIS
    Reads the AzureADSSOAcc password timestamp directly from a domain controller.
.DESCRIPTION
    Uses LDAP instead of AD Web Services so both validation reads come from the
    same PDC emulator without stale AD Web Services cache data.
.PARAMETER ComputerName
    The sAMAccountName without the trailing dollar sign.
.PARAMETER Server
    The domain controller used for the LDAP query.
.OUTPUTS
    System.DateTime in UTC.
#>
function Get-AzureADSSOAccPasswordLastSet {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        [Parameter(Mandatory = $true)]
        [string]$Server
    )

    $ldapRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server")
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = $ldapRoot
    try {
        # This is an LDAP filter, not a regex: & combines both clauses,
        # objectClass limits the result to computers, and the escaped PowerShell
        # dollar appends the literal suffix of a computer sAMAccountName.
        $searcher.Filter = "(&(objectClass=computer)(sAMAccountName=$ComputerName`$))"
        $searcher.PropertiesToLoad.Add('pwdLastSet') | Out-Null
        $result = $searcher.FindOne()
        if (!$result -or $result.Properties.pwdlastset.Count -eq 0) {
            throw [System.InvalidOperationException] "Could not read pwdLastSet for $ComputerName from PDC emulator $Server"
        }

        return [DateTime]::FromFileTimeUtc([Int64]$result.Properties.pwdlastset[0])
    }
    finally {
        $searcher.Dispose()
        $ldapRoot.Dispose()
    }
}
<#
.SYNOPSIS
    Writes a consistently formatted diagnostic record.
.DESCRIPTION
    Writes every message to the debug log and debug stream. Information, warning, and
    error records are also written to the Application event log and displayed in the
    console. Debug records are displayed through the verbose stream when -Verbose is
    specified.
.PARAMETER Message
    Text written to the diagnostic destinations.
.PARAMETER Severity
    Severity of the record: Debug, Information, Warning, or Error.
.PARAMETER EventID
    Numeric Application event log identifier. Debug records conventionally use 0.
.EXAMPLE
    Write-Log -Message 'Rollover completed' -Severity Information -EventID 3004

    Writes the message to the debug log, Application event log, and console.
.OUTPUTS
    None
#>
function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter (Mandatory = $true)]
        [Validateset('Error', 'Warning', 'Information', 'Debug') ]
        $Severity,
        [Parameter (Mandatory = $true)]
        [int]$EventID
    )


    # The CSV-like line includes enough context to correlate concurrent executions.
    $LogLine = "$([DateTimeOffset]::UtcNow.ToString('o')),$($PID), [$Severity],[$EventID], $Message"
    Write-Debug -Message $LogLine
    if (-not $script:IsWhatIf) {
        Add-Content -Path $LogFile -Value $LogLine -Force
    }

    # Debug entries remain file-only; operational severities are also surfaced to Windows.
    switch ($Severity) {
        'Error' {
            Write-Host $Message -ForegroundColor Red
            if (-not $script:IsWhatIf) {
                Add-Content -Path $LogFile -Value $Error[0].ScriptStackTrace
                Write-EventLog -LogName $eventLog -source $source -EventId $EventID -EntryType Error -Message $Message
            }
        }
        'Warning' {
            Write-Host $Message -ForegroundColor Yellow
            if (-not $script:IsWhatIf) {
                Write-EventLog -LogName $eventLog -source $source -EventId $EventID -EntryType Warning -Message $Message
            }
        }
        'Information' {
            Write-Host $Message
            if (-not $script:IsWhatIf) {
                Write-EventLog -LogName $eventLog -source $source -EventId $EventID -EntryType Information -Message $Message
            }
        }
        'Debug' {
            Write-Verbose -Message $Message
        }
    }
}

#region Script Variables

# Runtime identity and security settings used throughout the workflow.
$ScriptVersion = "1.1.20261009.1"
$passwordSize = 32
$eventLog = "Application"
$source = "AzureKrbRollOver"
$ResetPasswordExtendedRight = [Guid]'00299570-246d-11d0-a768-00aa006e0529'
$UserAccountControlProperty = [Guid]'bf967a68-0de6-11d0-a285-00aa003049e2'

# Synchronization is checked at a fixed interval for a bounded period.
$AzureSyncPollIntervalSeconds = 30
$AzureSyncTimeoutSeconds = 300
$TGTLifetimeHoursMin = 0
$TGTLifetimeHoursMax = 24

# Infrastructure constants for logging and Active Directory discovery.
[int]$MaxLogFileSize = 1048576 #Maximum size of the log file in bytes (1MB)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$GlobalCatalogPort = 3268
$AzureADSSOAccName = "AzureADSSOAcc"
#endregion

######################################################
# Main Script Logic
######################################################

#region Manage log file
# Display the version before any operation that can terminate the script.
Write-Host "Azure Kerberos Rollover - Version $ScriptVersion"

# Normalize the optional path before constructing a script-specific log file name.
# An absent, nonexistent, or unusable path falls back to LOCALAPPDATA; a supplied
# file path is reduced to its parent directory.
if ($LogPath -eq ""){
    $LogPath = $env:LOCALAPPDATA
} else {
    if (!(Test-Path $LogPath)){
        $LogPath = $env:LOCALAPPDATA
    } else {
        # Check if LogPath is a file, if so extract only the directory part
        if (Test-Path $LogPath -PathType Leaf){
            $LogPath = Split-Path $LogPath -Parent
        }
    }
}
$LogFile = "$LogPath\$(if($psise) {[System.IO.Path]::GetFileNameWithoutExtension($psise.CurrentFile.FullPath)} else {$MyInvocation.MyCommand}).log"
Write-Verbose "Log file: $LogFile"

try {
    # Event source creation requires administrative rights.
    if (-not $script:IsWhatIf -and -not [System.Diagnostics.EventLog]::SourceExists($source)) {
        Write-Verbose "Creating event source $source in log $eventLog"
        [System.Diagnostics.EventLog]::CreateEventSource($source, $eventLog)
    }
    elseif ($script:IsWhatIf) {
        Write-Verbose "WhatIf: Skip Windows event source creation."
    }
}
catch {
    $eventSourceError = "The event source $source could not be created. The script $($MyInvocation.MyCommand) is terminated. Please run the script with elevated privileges or create the event source $source manually. Error: $($_.Exception.Message)"
    Write-Host "ERROR: $eventSourceError" -ForegroundColor Red
    try {
        $logLine = "$([DateTimeOffset]::UtcNow.ToString('o')),$($PID), [Error],[1002], $eventSourceError"
        Add-Content -Path $LogFile -Value $logLine -Force -ErrorAction Stop
    }
    catch {
        Write-Host "ERROR: The error could not be written to log file $LogFile. Error: $($_.Exception.Message)" -ForegroundColor Red
    }
    exit 0x3EA
}

# Keep one previous 1 MB log generation to prevent unbounded disk usage.
if (-not $script:IsWhatIf -and (Test-Path $LogFile)){
    if ((Get-Item $LogFile ).Length -gt $MaxLogFileSize){
        if (Test-Path "$LogFile.sav"){
            Remove-Item "$LogFile.sav"
            Write-Verbose "Removed old log file $LogFile.sav"
        }
        Rename-Item -Path $LogFile -NewName "$logFile.sav"
    }
}
#endregion

Write-Log "=========================================" -Severity Debug -EventID 0
Write-Log "Script version $ScriptVersion" -Severity Debug -EventID 0
if ($script:IsWhatIf) {
    Write-Log "Running as $($env:USERNAME) in WhatIf mode; file and event logging are disabled" -Severity Information -EventID 3000
}
else {
    Write-Log "Running as $($env:USERNAME). Debug log: $LogFile" -Severity Information -EventID 3000
}
Write-Log -Message "The script started with $($MyInvocation.Line) - Process ID $($PID)" -Severity Debug -EventID 0
Write-Log -Message "Current user $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -Severity Debug -EventID 0
Write-Log -Message "Parameters: AzureADSSOModule: $AzureADSSOModule, RollOverADAccountName: $RollOverADAccountName, RollOverAccountUPN: $RollOverAccountUPN, LogPath: $LogPath, StartEntraConnectSync: $StartEntraConnectSync, TGTLifetimeHours: $TGTLifetimeHours, IgnoreTGTLifetimeCheck: $IgnoreTGTLifetimeCheck, Verbose: $($VerbosePreference -eq 'Continue'), WhatIf: $script:IsWhatIf" -Severity Debug -EventID 0

# These state variables let the final block distinguish success, WhatIf, declined
# confirmation, expected classified failures, and an unexpectedly incomplete run.
$scriptExitCode = 0
$scriptFailureMessage = $null
$scriptWasDeclined = $false
$rolloverCompleted = $false
$rolloverAccountMustBeDisabled = $false

Try {
    #region Import dependencies
    # AzureADSSO updates seamless SSO and ActiveDirectory performs directory operations.
    if (!(Get-Module -Name AzureADSSO)){
        Import-Module $AzureADSSOModule -Force -ErrorAction Stop
        Write-Log -Message "Imported AzureADSSO Module" -Severity Debug -EventID 0
    }
    if (!(Get-Module -Name ActiveDirectory)){
        Import-Module ActiveDirectory -Force -ErrorAction Stop
        Write-Log -Message "Imported ActiveDirectory Module" -Severity Debug -EventID 0
    }
    if ($StartEntraConnectSync -and !(Get-Module ADSync)){
        Import-Module ADSync -Force -ErrorAction Stop
        Write-Log -Message "Imported ADSync Module for the requested Entra Connect synchronization" -Severity Debug -EventID 0
    }

    #endregion
    #region Validate runtime inputs
    #region Validate TGT lifetime
    # Clamp rather than reject the value so unattended tasks retain deterministic
    # behavior while still recording the configuration problem.
    if ($TGTLifetimeHours -lt $TGTLifetimeHoursMin){
        Write-Log "The TGTLifeTime parameter is lower then $TGTLifeTimeHoursMin. Using $TGTLifeTimeHoursMin" -Severity Warning -EventID 3112
        $TGTLifetimeHours  = $TGTLifeTimeHoursMin
    } elseif ($TGTLifetimeHours -gt $TGTLifetimeHoursMax) {
        Write-Log "The TGTLifeTimeHours exceed the maximum value of $TGTLifeTimeHoursMax." -Severity Warning -EventID 3113
        $TGTLifeTimeHours = $TGTLifeTimeHoursMax
    }
    #endregion
    #region Validate rollover account
    # A Global Catalog is required because both the user UPN and AzureADSSOAcc can
    # belong to a forest domain other than the current domain.
    $GlobalCatalogServer = '{0}:{1}' -f (Get-ADDomainController -Discover -Service GlobalCatalog).HostName.Value, $GlobalCatalogPort
    Write-Log -Message "Using $GlobalCatalogServer as Global Catalog server" -Severity Debug -EventID 0

    $accountSearchServer = (Get-ADDomain).PDCEmulator
    $accountLookupValue = $RollOverADAccountName
    $accountLookupProperty = 'SamAccountName'

    # Regex: ^ and $ anchor the whole input; (?<Domain>[^\\]+) captures one or more
    # non-backslash characters as Domain; \\ matches the literal separator; and
    # (?<User>[^\\]+) captures the remaining non-backslash characters as User.
    if ($RollOverADAccountName -match '^(?<Domain>[^\\]+)\\(?<User>[^\\]+)$') {
        $accountDomain = Get-ADDomain -Identity $Matches.Domain -ErrorAction Stop
        $accountSearchServer = $accountDomain.PDCEmulator
        $accountLookupValue = $Matches.User
    }
    elseif ($RollOverADAccountName -like '*@*') {
        $accountSearchServer = $GlobalCatalogServer
        $accountLookupProperty = 'UserPrincipalName'
    }

    if ($accountLookupProperty -eq 'UserPrincipalName') {
        $rolloverUsers = @(Get-ADUser -Filter {UserPrincipalName -eq $accountLookupValue} -Server $accountSearchServer -Properties CanonicalName, SamAccountName, UserPrincipalName)
    }
    else {
        $rolloverUsers = @(Get-ADUser -Filter {SamAccountName -eq $accountLookupValue} -Server $accountSearchServer -Properties CanonicalName, SamAccountName, UserPrincipalName)
    }

    if ($rolloverUsers.Count -eq 0) {
        Write-Log -Message "Can not find $RollOverADAccountName in the Active Directory forest" -Severity Error -EventID 3109
        throw [System.ArgumentException] "The Kerberos RollOver Account $RollOverADAccountName does not exist in the Active Directory forest"
    }
    if ($rolloverUsers.Count -gt 1) {
        Write-Log -Message "Found multiple Active Directory accounts matching $RollOverADAccountName" -Severity Error -EventID 3109
        throw [System.ArgumentException] "The Kerberos RollOver Account $RollOverADAccountName is not unique"
    }

    $RollOverADUser = $rolloverUsers[0]
    # -split treats / as its regex delimiter and limits the result to two parts;
    # index 0 is the DNS domain at the start of CanonicalName.
    $rollOverUserDomainName = ($RollOverADUser.CanonicalName -split '/', 2)[0]
    $rollOverUserDomain = Get-ADDomain -Identity $rollOverUserDomainName -ErrorAction Stop
    $RollOverSamAccountName = $RollOverADUser.SamAccountName
    $ADUser = "$($rollOverUserDomain.NetBIOSName)\$RollOverSamAccountName"
    Write-Log -Message "Resolved $RollOverADAccountName to $ADUser" -Severity Debug -EventID 0
#endregion
#endregion


    # Prefer the directory value so callers only need to supply a UPN when it differs.
    if (!$RollOverAccountUPN) {
        $RollOverAccountUPN = $RollOverADUser.UserPrincipalName
    }
    if (!$RollOverAccountUPN) {
        Write-Log -Message "The Active Directory account $ADUser does not have a user principal name" -Severity Error -EventID 3109
        throw [System.ArgumentException] "The Kerberos RollOver Account $ADUser does not have a user principal name"
    }
    write-Log -Message "Using $RollOverAccountUPN as UPN for the Kerberos RollOver Account" -Severity Debug -EventID 0

    # AzureADSSOAcc can reside in another domain, so discover it forest-wide first.
    $gcAzureADSsoAcc = Get-ADComputer -Filter {Name -eq $AzureADSSOAccName } -Server "$GlobalCatalogServer" -Properties CanonicalName
    if (!$gcAzureADSsoAcc) {
        Write-Log -Message "AzureADSSOAcc computer account not found in the Global Catalog. Please ensure the Azure AD Connect is installed and configured." -Severity Error -EventID 3106
        throw [System.ArgumentException] "The AzureADSSOAcc computer account was not found in the Global Catalog"
    }
    # CanonicalName begins with the owning DNS domain; query that domain for pwdLastSet.
    # Regex: [^/]+ matches one or more characters that are not a slash. Because
    # -match returns the first match, $Matches[0] is the leading DNS domain.
    $gcAzureADSsoAcc.CanonicalName -match "[^/]+" |Out-Null
    $DomainName = $matches[0]
    $AzureADSSODomain = Get-ADDomain -Identity $DomainName -ErrorAction Stop
    $PDCEmulator = $AzureADSSODomain.PDCEmulator
    $AzureADSsoAcc = Get-ADcomputer -Filter {Name -eq $AzureADSSOAccName} -Server $PDCEmulator

    # Validate both security contexts before changing the rollover account password:
    # the executing identity must reset the worker password, and the worker identity
    # must update AzureADSSOAcc.
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if ($currentIdentity.IsSystem) {
        # Local SYSTEM authenticates to remote AD services as the server computer.
        # Resolve the sAMAccountName first without tokenGroups. The constructed
        # tokenGroups attribute is available only through an LDAP base search, so
        # the second lookup uses the resolved distinguished name as its identity.
        $localComputerDomain = Get-ADDomain -ErrorAction Stop
        $localComputerReference = Get-ADComputer -Identity "$env:COMPUTERNAME`$" -Server $localComputerDomain.PDCEmulator -ErrorAction Stop
        $localComputer = Get-ADComputer -Identity $localComputerReference.DistinguishedName -Server $localComputerDomain.PDCEmulator -Properties SID, tokenGroups -ErrorAction Stop
        $currentPrincipal = "$($localComputerDomain.NetBIOSName)\$($localComputer.SamAccountName)"
        $currentPrincipalSids = @($localComputer.SID.Value)
        foreach ($tokenGroup in $localComputer.tokenGroups) {
            if ($tokenGroup -is [System.Security.Principal.SecurityIdentifier]) {
                $currentPrincipalSids += $tokenGroup.Value
            }
            elseif ($tokenGroup -is [byte[]]) {
                $currentPrincipalSids += (
                    New-Object System.Security.Principal.SecurityIdentifier($tokenGroup, 0)
                ).Value
            }
            else {
                throw [System.InvalidOperationException] "Unsupported tokenGroups SID type $($tokenGroup.GetType().FullName) for $currentPrincipal"
            }
        }
    }
    else {
        # For an interactive administrator, WindowsIdentity already exposes the user
        # SID and effective local/domain group SIDs in the access token.
        $currentPrincipal = $currentIdentity.Name
        $currentPrincipalSids = @($currentIdentity.User.Value)
        foreach ($groupSid in $currentIdentity.Groups) {
            $currentPrincipalSids += $groupSid.Value
        }
    }
    # Include Everyone and Authenticated Users because ACLs commonly grant rights to
    # these well-known principals rather than directly to the account.
    $currentPrincipalSids += 'S-1-1-0', 'S-1-5-11'
    $currentPrincipalSids = @($currentPrincipalSids | Select-Object -Unique)

    $canResetRolloverAccount = Test-ADObjectRight `
        -DistinguishedName $RollOverADUser.DistinguishedName `
        -PrincipalSids $currentPrincipalSids `
        -RequiredRight ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) `
        -ObjectType $ResetPasswordExtendedRight
    if (!$canResetRolloverAccount) {
        Write-Log -Message "$currentPrincipal does not have Reset Password permission on rollover account $ADUser" -Severity Error -EventID 3102
        throw [System.UnauthorizedAccessException] "$currentPrincipal can not reset the password of rollover account $ADUser"
    }
    $canWriteRolloverAccountState = Test-ADObjectRight `
        -DistinguishedName $RollOverADUser.DistinguishedName `
        -PrincipalSids $currentPrincipalSids `
        -RequiredRight ([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) `
        -ObjectType $UserAccountControlProperty
    $initialRolloverAccountState = Get-ADUser -Identity $RollOverADUser.DistinguishedName -Server $rollOverUserDomain.PDCEmulator -Properties Enabled -ErrorAction Stop
    if (!$initialRolloverAccountState.Enabled -and !$canWriteRolloverAccountState) {
        Write-Log -Message "$currentPrincipal does not have Write permission on userAccountControl for rollover account $ADUser" -Severity Error -EventID 3102
        throw [System.UnauthorizedAccessException] "$currentPrincipal can not enable disabled rollover account $ADUser"
    }
    if ($canWriteRolloverAccountState) {
        Write-Log -Message "$currentPrincipal has Reset Password and account-state permissions on rollover account $ADUser" -Severity Debug -EventID 0
    }
    else {
        Write-Log -Message "Rollover account $ADUser is already enabled. Continuing without detected Write userAccountControl permission for $currentPrincipal; the final disable operation will report an error if the permission is unavailable" -Severity Debug -EventID 0
    }

    # Read tokenGroups from the worker account's PDC to evaluate transitive group ACEs.
    $rollOverUserSecurity = Get-ADUser -Identity $RollOverADUser.DistinguishedName -Server $rollOverUserDomain.PDCEmulator -Properties tokenGroups, SID -ErrorAction Stop
    $rollOverPrincipalSids = @($rollOverUserSecurity.SID.Value)
    foreach ($tokenGroup in $rollOverUserSecurity.tokenGroups) {
        if ($tokenGroup -is [System.Security.Principal.SecurityIdentifier]) {
            $rollOverPrincipalSids += $tokenGroup.Value
        }
        elseif ($tokenGroup -is [byte[]]) {
            $rollOverPrincipalSids += (
                New-Object System.Security.Principal.SecurityIdentifier($tokenGroup, 0)
            ).Value
        }
        else {
            throw [System.InvalidOperationException] "Unsupported tokenGroups SID type $($tokenGroup.GetType().FullName) for $ADUser"
        }
    }
    $rollOverPrincipalSids += 'S-1-1-0', 'S-1-5-11'
    $rollOverPrincipalSids = @($rollOverPrincipalSids | Select-Object -Unique)

    # Update-AzureADSSOForest requires object write access plus the control access
    # right that resets the AzureADSSOAcc computer password.
    $missingAzureADSSORights = @()
    if (!(Test-ADObjectRight -DistinguishedName $AzureADSsoAcc.DistinguishedName -PrincipalSids $rollOverPrincipalSids -RequiredRight ([System.DirectoryServices.ActiveDirectoryRights]::GenericWrite))) {
        $missingAzureADSSORights += 'Write'
    }
    if (!(Test-ADObjectRight -DistinguishedName $AzureADSsoAcc.DistinguishedName -PrincipalSids $rollOverPrincipalSids -RequiredRight ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ObjectType $ResetPasswordExtendedRight)) {
        $missingAzureADSSORights += 'Reset Password'
    }
    if ($missingAzureADSSORights.Count -gt 0) {
        $missingRightsText = $missingAzureADSSORights -join ', '
        Write-Log -Message "$ADUser is missing $missingRightsText permission on $AzureADSSOAccName" -Severity Error -EventID 3102
        throw [System.UnauthorizedAccessException] "$ADUser is missing $missingRightsText permission on $AzureADSSOAccName"
    }
    Write-Log -Message "$ADUser has Write and Reset Password permissions on $AzureADSSOAccName" -Severity Debug -EventID 0

    $AzureADSsoAccPwdLastSetBefore = Get-AzureADSSOAccPasswordLastSet -ComputerName $AzureADSSOAccName -Server $PDCEmulator
    $AzureADSsoAccPwdLastSetBeforeText = $AzureADSsoAccPwdLastSetBefore.ToString('o')
    Write-Log -Message "The AzureADSSOAcc computer account password timestamp before rollover is $AzureADSsoAccPwdLastSetBeforeText UTC (read from PDC emulator $PDCEmulator)" -Severity Debug -EventID 0
    # Avoid invalidating Kerberos tickets that may still be active from the last rollover.
    if ($IgnoreTGTLifetimeCheck){
        Write-Log -Message "Skipping the TGT lifetime check as the IgnoreTGTLifetimeCheck switch is set" -Severity Warning -EventID 3008
    } else {
        if (([DateTime]::UtcNow - $AzureADSsoAccPwdLastSetBefore).Totalhours -le $TGTLifetimeHours) {
            Write-Log -Message "The AzureADSSOAcc last password reset at $AzureADSsoAccPwdLastSetBeforeText UTC does not exceed the current TGT lifetime of $TGTLifetimeHours hours" -Severity Warning -EventID 3107
            throw [System.InvalidOperationException] "The AzureADSSOAcc password last set is $AzureADSsoAccPwdLastSetBeforeText UTC and does not exceed the TGT lifetime"
        }
    }

    # WhatIf still performs every read-only discovery and permission check, then
    # presents the exact mutations that ShouldProcess will suppress.
    if ($script:IsWhatIf) {
        $passwordAgeHours = [Math]::Round(([DateTime]::UtcNow - $AzureADSsoAccPwdLastSetBefore).TotalHours, 2)
        $tgtValidation = if ($IgnoreTGTLifetimeCheck) {
            'Bypassed by IgnoreTGTLifetimeCheck'
        }
        else {
            "Passed: password age $passwordAgeHours hours exceeds required $TGTLifetimeHours hours"
        }
        $syncPlan = if ($StartEntraConnectSync) {
            'Start an Entra Connect delta synchronization'
        }
        else {
            'Do not start Entra Connect synchronization; wait for external synchronization'
        }

        Write-Host ''
        Write-Host 'WhatIf validation summary' -ForegroundColor Cyan
        Write-Host "  [PASS] Rollover account: $ADUser" -ForegroundColor Green
        Write-Host "  [PASS] Microsoft Entra UPN: $RollOverAccountUPN" -ForegroundColor Green
        if ($canWriteRolloverAccountState) {
            Write-Host "  [PASS] Execution principal $currentPrincipal can enable, reset, and disable the rollover account" -ForegroundColor Green
        }
        else {
            Write-Host "  [WARN] Rollover account is already enabled and can be reset, but $currentPrincipal lacks detected permission to disable it at the end" -ForegroundColor Yellow
        }
        Write-Host "  [PASS] $ADUser can change and reset the password of $AzureADSSOAccName in $DomainName" -ForegroundColor Green
        Write-Host "  [PASS] TGT lifetime check: $tgtValidation" -ForegroundColor Green
        Write-Host ''
        Write-Host 'Planned actions' -ForegroundColor Cyan
        Write-Host "  1. Read the current Enabled state of $ADUser from $($rollOverUserDomain.PDCEmulator)"
        Write-Host "  2. Enable and verify $ADUser only when it is currently disabled"
        Write-Host "  3. Generate a new $passwordSize-character password in process memory"
        Write-Host "  4. Reset the password of $ADUser on $($rollOverUserDomain.PDCEmulator)"
        Write-Host "  5. $syncPlan"
        Write-Host "  6. Check every $AzureSyncPollIntervalSeconds seconds for up to $AzureSyncTimeoutSeconds seconds whether the new password is available in Microsoft Entra ID"
        Write-Host "  7. Run Update-AzureADSSOForest as $ADUser"
        Write-Host "  8. Verify the $AzureADSSOAccName password timestamp on the PDC emulator in $DomainName"
        Write-Host "  9. Disable $ADUser before the script exits"
        Write-Host ''
    }

    # One ShouldProcess boundary covers all dependent mutations so confirmation cannot
    # leave the workflow halfway through by approving individual steps separately.
    $rolloverTarget = "$RollOverADAccountName and $AzureADSSOAccName"
    $rolloverAction = "Temporarily enable the rollover account, reset its password, update the seamless SSO Kerberos key, and disable the account"
    if (-not $PSCmdlet.ShouldProcess($rolloverTarget, $rolloverAction)) {
        if (!$script:IsWhatIf) {
            $scriptWasDeclined = $true
            Write-Log -Message "Rollover skipped because confirmation was declined" -Severity Information -EventID 3000
        }
        return
    }

    # Once the rollover starts, the account must be disabled again regardless of
    # its initial state or any later failure.
    $rolloverAccountMustBeDisabled = $true
    $rolloverAccountState = Get-ADUser -Identity $RollOverADUser.DistinguishedName -Server $rollOverUserDomain.PDCEmulator -Properties Enabled -ErrorAction Stop
    if ($rolloverAccountState.Enabled) {
        Write-Log -Message "Kerberos RollOver Account $ADUser is already enabled; no enable operation is required" -Severity Debug -EventID 0
    }
    else {
        try {
            Enable-ADAccount -Identity $RollOverADUser.DistinguishedName -Server $rollOverUserDomain.PDCEmulator -ErrorAction Stop
        }
        catch {
            $enableFailure = $_
            if ($enableFailure.Exception -is [System.UnauthorizedAccessException] -or
                $enableFailure.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::PermissionDenied) {
                throw [System.UnauthorizedAccessException] "The disabled Kerberos RollOver Account $ADUser could not be enabled because $currentPrincipal lacks Write userAccountControl permission. Details: $($enableFailure.Exception.Message)"
            }
            throw [System.InvalidOperationException] "The disabled Kerberos RollOver Account $ADUser could not be enabled. Details: $($enableFailure.Exception.Message)"
        }

        $enabledRolloverAccount = Get-ADUser -Identity $RollOverADUser.DistinguishedName -Server $rollOverUserDomain.PDCEmulator -Properties Enabled -ErrorAction Stop
        if (!$enabledRolloverAccount.Enabled) {
            throw [System.InvalidOperationException] "The Kerberos RollOver Account $ADUser remained disabled after Enable-ADAccount"
        }
        Write-Log -Message "Enabled Kerberos RollOver Account: $ADUser" -Severity Information -EventID 3009
    }

    # Reset the synchronized identity before publishing the same secret to seamless SSO.
    # The plaintext exists only in process/job memory because the AD and AzureADSSO
    # APIs both require credentials derived from the same newly generated secret.
    Write-Log -Message "Generate a new random password for the Kerberos RollOver Account" -Severity Debug -EventID 0
    $secPwd = New-RandomPassword -length $passwordSize
    Set-ADAccountPassword -Identity $RollOverADUser.DistinguishedName -Server $rollOverUserDomain.PDCEmulator -NewPassword (ConvertTo-SecureString $secPwd -AsPlainText -Force) -Reset -ErrorAction Stop
    Write-Log -Message "Password for Kerberos RollOver Account $ADUser has been reset" -Severity Debug -EventID 0
    Write-Log -Message "Reset Password for Kerberos RollOver Account: $ADUser" -Severity Information -EventID 3001
    if ($StartEntraConnectSync) {
        Write-Log -Message "Starting Entra Connect delta synchronization" -Severity Information -EventID 3002
        Start-ADSyncSyncCycle -PolicyType Delta -ErrorAction Stop
    } else {
        Write-Log -Message "Entra Connect synchronization was not requested" -Severity Debug -EventID 0
    }
    # Verify that password hash synchronization has made the new credential usable in
    # Microsoft Entra ID before Update-AzureADSSOForest relies on it.
    $syncStartedAt = Get-Date
    $syncDeadline = $syncStartedAt.AddSeconds($AzureSyncTimeoutSeconds)
    $syncAttempt = 0
    $passwordSynchronized = $false
    $lastPasswordSyncFailure = $null
    while (-not $passwordSynchronized -and (Get-Date) -lt $syncDeadline) {
        $syncAttempt++
        # Anchor retries to the original start time so job overhead does not accumulate
        # into progressively later checks.
        $nextCheckAt = $syncStartedAt.AddSeconds($syncAttempt * $AzureSyncPollIntervalSeconds)
        $waitSeconds = [Math]::Max(0, [Math]::Ceiling(($nextCheckAt - (Get-Date)).TotalSeconds))
        if ($waitSeconds -gt 0) {
            Write-Host "Waiting $waitSeconds seconds before checking password synchronization (attempt $syncAttempt)..." -ForegroundColor Cyan
            Start-Sleep -Seconds $waitSeconds
        }

        Write-Host "Checking whether the updated password is available in Microsoft Entra ID (attempt $syncAttempt)..." -ForegroundColor Cyan
        Write-Log -Message "Checking password synchronization for $RollOverAccountUPN (attempt $syncAttempt)" -Severity Debug -EventID 0

        $syncCheckJob = $null
        try {
            # Keep the child process in the scheduled task's SYSTEM context. Windows
            # does not support alternate-credential process creation when the caller
            # is LocalSystem. The AzureADSSO cmdlet receives the worker credential
            # explicitly instead.
            $syncCheckJob = Start-Job -ScriptBlock {
                param ($AzureADSSOModule, $RollOverAccountUPN, $secPwd)

                $ErrorActionPreference = 'Stop'
                try {
                    Import-Module $AzureADSSOModule -Force
                    $securePassword = ConvertTo-SecureString $secPwd -AsPlainText -Force
                    $cloudCredential = New-Object System.Management.Automation.PSCredential (
                        $RollOverAccountUPN,
                        $securePassword
                    )
                    New-AzureADSSOAuthenticationContext -CloudCredentials $cloudCredential | Out-Null
                    [pscustomobject]@{
                        Success = $true
                        ErrorMessage = $null
                    }
                }
                catch {
                    # Preserve the complete inner-exception chain because WS-Trust and
                    # MSAL often place the actionable AADSTS detail below the top level.
                    $errorMessages = @()
                    if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                        $errorMessages += $_.ErrorDetails.Message
                    }
                    $exception = $_.Exception
                    while ($exception) {
                        if ($exception.Message) {
                            $errorMessages += $exception.Message
                        }
                        $exception = $exception.InnerException
                    }
                    if ($_.CategoryInfo) {
                        $errorMessages += $_.CategoryInfo.ToString()
                    }
                    if ($_.FullyQualifiedErrorId) {
                        $errorMessages += "Error ID: $($_.FullyQualifiedErrorId)"
                    }
                    [pscustomobject]@{
                        Success = $false
                        ErrorMessage = (($errorMessages |
                            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                            Select-Object -Unique) -join ' | ')
                    }
                }
            } -ArgumentList $AzureADSSOModule, $RollOverAccountUPN, $secPwd

            # A hung authentication attempt must not consume the entire five-minute
            # synchronization window.
            $completedJob = Wait-Job -Job $syncCheckJob -Timeout $AzureSyncPollIntervalSeconds
            if (-not $completedJob) {
                Stop-Job -Job $syncCheckJob
                throw [System.TimeoutException] "The password synchronization check exceeded the remaining timeout"
            }
            if ($syncCheckJob.State -ne 'Completed') {
                $jobFailureMessage = Get-BackgroundJobErrorMessage -Job $syncCheckJob
                throw [System.InvalidOperationException] "The password synchronization authentication job ended in state $($syncCheckJob.State). Details: $jobFailureMessage"
            }

            # Receive output and errors separately. -ErrorAction Stop would discard
            # the structured result as soon as the job error stream contains a record.
            $syncJobErrors = @()
            $syncJobOutput = @(Receive-Job -Job $syncCheckJob -ErrorVariable syncJobErrors -ErrorAction SilentlyContinue)
            $authenticationResult = @(
                $syncJobOutput |
                    Where-Object { $null -ne $_.PSObject.Properties['Success'] }
            ) | Select-Object -Last 1
            if (!$authenticationResult) {
                $jobFailureMessage = Get-BackgroundJobErrorMessage -ErrorRecords $syncJobErrors -Job $syncCheckJob
                throw [System.InvalidOperationException] "The password synchronization authentication job returned no result. Details: $jobFailureMessage"
            }

            if (!$authenticationResult.Success) {
                $authenticationErrorMessage = [string]$authenticationResult.ErrorMessage
                if ([string]::IsNullOrWhiteSpace($authenticationErrorMessage)) {
                    $authenticationErrorMessage = Get-BackgroundJobErrorMessage -ErrorRecords $syncJobErrors -Job $syncCheckJob
                }
                $lastPasswordSyncFailure = $authenticationErrorMessage
                $failureCategory = Get-EntraAuthenticationFailureCategory -Message $authenticationErrorMessage
                # Policy blocks are deterministic and terminate immediately. Rejected
                # credentials remain retryable because synchronization can still be pending.
                switch ($failureCategory) {
                    'AuthenticationPolicyBlocked' {
                        $scriptExitCode = 0x3EC
                        throw [System.Security.Authentication.AuthenticationException] "Microsoft Entra authentication for $RollOverAccountUPN was blocked by an MFA or Conditional Access requirement. The noninteractive rollover can not continue. Review the failed sign-in, per-user MFA, and the applied Conditional Access policies. Details: $authenticationErrorMessage"
                    }
                    'InvalidCredentials' {
                        Write-Host "Microsoft Entra rejected the updated credentials. The new password may not be synchronized yet; no explicit MFA or Conditional Access error code was returned." -ForegroundColor Yellow
                    }
                    Default {
                        Write-Host "Microsoft Entra authentication failed without a recognized MFA or Conditional Access error code. The check will be retried." -ForegroundColor Yellow
                    }
                }
                Write-Log -Message "Password synchronization check failed on attempt $syncAttempt ($failureCategory): $authenticationErrorMessage" -Severity Debug -EventID 0
                continue
            }

            if ($syncJobErrors.Count -gt 0) {
                $jobWarningMessage = Get-BackgroundJobErrorMessage -ErrorRecords $syncJobErrors -Job $syncCheckJob
                Write-Log -Message "The successful authentication job also wrote diagnostic records: $jobWarningMessage" -Severity Debug -EventID 0
            }
            $passwordSynchronized = $true
            Write-Host "The updated password is available in Microsoft Entra ID." -ForegroundColor Green
            Write-Log -Message "The updated password for $RollOverAccountUPN is available in Microsoft Entra ID" -Severity Information -EventID 3003
        }
        catch {
            # Preserve classified policy failures; transient job, transport, and stale
            # credential failures are logged and retried until the shared deadline.
            if ($_.Exception -is [System.Security.Authentication.AuthenticationException]) {
                throw
            }
            $lastPasswordSyncFailure = $_.Exception.Message
            Write-Host "The updated password is not available in Microsoft Entra ID yet." -ForegroundColor Yellow
            Write-Log -Message "Password synchronization check failed on attempt $syncAttempt`: $($_.Exception.Message)" -Severity Debug -EventID 0
        }
        finally {
            if ($syncCheckJob) {
                Remove-Job -Job $syncCheckJob -Force
            }
        }
    }

    if (-not $passwordSynchronized) {
        $scriptExitCode = 0x3EB
        $message = "Microsoft Entra authentication with the updated password for $RollOverAccountUPN could not be verified after five minutes"
        if ($lastPasswordSyncFailure) {
            $message += ". Last authentication error: $lastPasswordSyncFailure"
        }
        Write-Host $message -ForegroundColor Red
        Write-Log -Message $message -Severity Error -EventID 3114
        throw [System.TimeoutException] $message
    }

    #region Update seamless SSO with explicit rollover credentials
Write-Log -Message "Using explicit cloud and on-premises credentials for $ADUser to update the Azure Kerberos object" -Severity Debug -EventID 0
# The child process remains under SYSTEM because alternate-credential process
# creation is unsupported for a LocalSystem caller. AzureADSSO receives separate
# cloud and on-premises PSCredentials created from the synchronized secret.
$ADSSResetJob = Start-Job -ScriptBlock {
    param ($AzureADSSOModule, $RollOverAccountUPN, $ADUser, $secPwd, $VerboseEnabled)
    $verboseParameters = if ($VerboseEnabled) { @{ Verbose = $true } } else { @{} }
    Import-Module $AzureADSSOModule -ErrorAction Stop @verboseParameters
    $secAzPwd = ConvertTo-SecureString -String $secPwd -AsPlainText -Force
    [pscredential]$CredKerbRollOverAzCred = New-Object System.Management.Automation.PSCredential ($RollOverAccountUPN, $secAzPwd);
    [pscredential]$CredKerbRollOverADCred = New-Object System.Management.Automation.PSCredential ($ADUser, $secAzPwd);
    # Authenticate first so a later access-denied error can be attributed to the
    # forest update rather than incorrectly reported as a login failure.
    try {
        New-AzureADSSOAuthenticationContext -CloudCredentials $CredKerbRollOverAzCred -ErrorAction Stop @verboseParameters | Out-Null
    }
    catch {
        throw [System.InvalidOperationException] "Microsoft Entra authentication failed while preparing the AzureADSSO forest update. The earlier password synchronization check succeeded, but the update job could not create its authentication context. Details: $($_.Exception.Message)"
    }

    try {
        Update-AzureADSSOForest -PreserveCustomPermissionsOnDesktopSsoAccount -OnPremCredentials $CredKerbRollOverADCred -ErrorAction Stop @verboseParameters | Out-Null
    }
    catch {
        # Regex: (?i) makes the text comparison case-insensitive; (?:is )? is an
        # optional noncapturing group, matching both "access denied" and
        # "access is denied".
        if ($_.Exception -is [System.UnauthorizedAccessException] -or
            $_.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::PermissionDenied -or
            $_.Exception.Message -match '(?i)access (?:is )?denied') {
            throw [System.UnauthorizedAccessException] "Update-AzureADSSOForest was denied after Microsoft Entra authentication succeeded. Verify that $RollOverAccountUPN has the Hybrid Identity Administrator role and that $ADUser has the required Active Directory permissions on AzureADSSOAcc. Details: $($_.Exception.Message)"
        }
        throw [System.InvalidOperationException] "Update-AzureADSSOForest failed after Microsoft Entra authentication succeeded. Details: $($_.Exception.Message)"
    }
} -ArgumentList $AzureADSSOModule, $RollOverAccountUPN, $ADUser, $secPwd, ($VerbosePreference -eq 'Continue')
Write-Log -Message "Waiting for AzureADSSO Forest update job to complete..." -Severity Debug -EventID 0
try {
    # Check the job state explicitly because Wait-Job itself can return successfully
    # even when the child runspace failed.
    $null = Wait-Job -Job $ADSSResetJob -ErrorAction Stop
    if ($ADSSResetJob.State -ne 'Completed') {
        $jobFailureMessage = Get-BackgroundJobErrorMessage -Job $ADSSResetJob
        throw [System.InvalidOperationException] "AzureADSSO Forest update job ended in state $($ADSSResetJob.State). Details: $jobFailureMessage"
    }

    $updateJobErrors = @()
    Receive-Job -Job $ADSSResetJob -ErrorVariable updateJobErrors -ErrorAction SilentlyContinue | Out-Null
    if ($updateJobErrors.Count -gt 0) {
        $jobFailureMessage = Get-BackgroundJobErrorMessage -ErrorRecords $updateJobErrors -Job $ADSSResetJob
        throw [System.InvalidOperationException] "AzureADSSO Forest update job reported an error. Details: $jobFailureMessage"
    }
    Write-Log -Message "AzureADSSO Forest update completed" -Severity Information -EventID 3002
}
finally {
    Remove-Job -Job $ADSSResetJob -Force -ErrorAction Continue
}

    #endregion
    # A successful rollover must advance pwdLastSet on the same PDC emulator that
    # supplied the baseline value. A recent but unchanged timestamp is not success.
    $AzureADSsoAccPwdLastSetAfter = Get-AzureADSSOAccPasswordLastSet -ComputerName $AzureADSSOAccName -Server $PDCEmulator
    $AzureADSsoAccPwdLastSetAfterText = $AzureADSsoAccPwdLastSetAfter.ToString('o')
    Write-Log -Message "The AzureADSSOAcc computer account password timestamp after rollover is $AzureADSsoAccPwdLastSetAfterText UTC (read from PDC emulator $PDCEmulator)" -Severity Debug -EventID 0
    if ($AzureADSsoAccPwdLastSetAfter -gt $AzureADSsoAccPwdLastSetBefore) {
        Write-Log -Message "The AzureADSSOAcc computer account password timestamp advanced from $AzureADSsoAccPwdLastSetBeforeText UTC to $AzureADSsoAccPwdLastSetAfterText UTC" -Severity Debug -EventID 0
    } else {
        $message = "The AzureADSSOAcc computer account password timestamp did not advance. Before: $AzureADSsoAccPwdLastSetBeforeText UTC. After: $AzureADSsoAccPwdLastSetAfterText UTC"
        Write-Log -Message $message -Severity Error -EventID 3108
        throw [System.InvalidOperationException] $message
    }
    Write-Log -Message "Successfully updated the Azure Kerberos object" -Severity Information -EventID 3004
    $rolloverCompleted = $true
}
catch{
    # Preserve a previously assigned classified exit code; otherwise use the generic
    # failure code and map the exception to an operational event ID below.
    $caughtError = $_
    if ($scriptExitCode -eq 0) {
        $scriptExitCode = 0x1
    }
    $scriptFailureMessage = $caughtError.Exception.Message
    Write-Log -Message "An error occurred: $scriptFailureMessage $($caughtError.InvocationInfo.PositionMessage)" -Severity Debug -EventID 0
    switch ($caughtError.Exception){
        {$_ -is [System.InvalidOperationException]}{
            Write-Log -Message "Invalid operation: $scriptFailureMessage" -Severity Error -EventID 3198
            break
        }
        {$_ -is [System.IO.FileNotFoundException]}{
            if ($caughtError.CategoryInfo.TargetName -like "*AzureADSSO.psd1"){
                Write-log -Message "Take care the script is running on a Microsoft Entra Connect server. Missing $($caughtError.CategoryInfo.TargetName) " -Severity Error -EventID 3111
            } else {
                Write-log -Message "Please install the required PowerShell modules $($caughtError.CategoryInfo.TargetName) " -Severity Error -EventID 3111
            }
            break
        }
        {$_ -is [System.UnauthorizedAccessException] -or $caughtError.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::PermissionDenied}{
            Write-log -Message "Access denied during the rollover: $scriptFailureMessage" -Severity Error -EventID 3102
            break
        }
        {$_ -is [System.ArgumentException]}{
            Write-Log -Message "Invalid argument: $scriptFailureMessage" -Severity Error -EventID 3110
            break
        }
        {$_ -is [System.TimeoutException]}{
            Write-Log -Message "Password synchronization timed out: $($_)" -Severity Debug -EventID 0
            break
        }
        {$_ -is [System.Security.Authentication.AuthenticationException]}{
            Write-Log -Message $scriptFailureMessage -Severity Error -EventID 3103
            break
        }
        {$_ -is [System.Management.Automation.CommandNotFoundException]}{
            Write-Log -Message "A required PowerShell command is missing. Please ensure the required PowerShell modules are installed." -Severity Error -EventID 3110
            break
        }
        Default {
            Write-Log -Message "An error occurred: $scriptFailureMessage" -Severity Error -EventID 3199
        }
    }
}
finally {
    if ($rolloverAccountMustBeDisabled) {
        try {
            Disable-ADAccount -Identity $RollOverADUser.DistinguishedName -Server $rollOverUserDomain.PDCEmulator -ErrorAction Stop
            $disabledRolloverAccount = Get-ADUser -Identity $RollOverADUser.DistinguishedName -Server $rollOverUserDomain.PDCEmulator -Properties Enabled -ErrorAction Stop
            if ($disabledRolloverAccount.Enabled) {
                throw [System.InvalidOperationException] "The account remained enabled after Disable-ADAccount"
            }
            Write-Log -Message "Disabled Kerberos RollOver Account: $ADUser" -Severity Information -EventID 3010
        }
        catch {
            $disableFailureDetails = $_
            $permissionFailure = (
                $disableFailureDetails.Exception -is [System.UnauthorizedAccessException] -or
                $disableFailureDetails.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::PermissionDenied
            )
            if ($permissionFailure) {
                $disableFailureMessage = "The Kerberos RollOver Account $ADUser could not be disabled because $currentPrincipal lacks Write userAccountControl permission. Details: $($disableFailureDetails.Exception.Message)"
            }
            else {
                $disableFailureMessage = "The Kerberos RollOver Account $ADUser could not be disabled. Verify Write userAccountControl permission for $currentPrincipal. Details: $($disableFailureDetails.Exception.Message)"
            }
            if ([string]::IsNullOrWhiteSpace($scriptFailureMessage)) {
                $scriptFailureMessage = $disableFailureMessage
            }
            else {
                $scriptFailureMessage = "$scriptFailureMessage. Cleanup error: $disableFailureMessage"
            }
            $scriptExitCode = 0x1
            Write-Log -Message $disableFailureMessage -Severity Error -EventID 3102
        }
    }

    # The completion invariant prevents an early return or unexpected branch from
    # reporting success unless WhatIf/decline was intentional or rolloverCompleted
    # was set only after final PDC verification.
    if ($scriptExitCode -ne 0) {
        Write-Log -Message "Script terminated with error: $scriptFailureMessage" -Severity Warning -EventID 3196
    }
    elseif ($script:IsWhatIf) {
        Write-Log -Message "WhatIf validation completed successfully. No changes were made." -Severity Information -EventID 3006
    }
    elseif ($scriptWasDeclined) {
        Write-Log -Message "Script completed without changes because confirmation was declined" -Severity Information -EventID 3006
    }
    elseif (!$rolloverCompleted) {
        $scriptExitCode = 0x1
        $scriptFailureMessage = "The rollover workflow ended before completion"
        Write-Log -Message $scriptFailureMessage -Severity Error -EventID 3199
    }
    else {
        Write-Log -Message "Script completed successfully" -Severity Information -EventID 3006
    }
    Write-Log "=========================================" -Severity Debug -EventID 0
}

exit $scriptExitCode
