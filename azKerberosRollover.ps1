<#PSScriptInfo

.VERSION 0.1.20261009.2
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
    5. Generates a new password and resets the on-premises rollover account.
    6. Optionally starts an Entra Connect delta synchronization and checks every
       30 seconds for up to five minutes whether the new password is available.
    7. Runs the AzureADSSO forest update in a background job under the rollover account.
    8. Reads pwdLastSet from the PDC emulator to verify that the update succeeded.

    Return codes:
    0x0    Success
    0x1    The rollover workflow terminated with an error.
    0x3EA  The Windows event source could not be created.
    0x3EB  The worker account password was not synchronized within five minutes.
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
    $chars += [char[]](33)      # Special characters !
    $chars += [char[]](35..38)  # Special characters # $ % & ' ( ) * + , - . /
    $chars += [char[]](40..47)  # Special characters : ; < = > ? @


    $password = -join ((1..$length) | ForEach-Object { $chars | Get-Random })
    return $password
}
<#
.SYNOPSIS
    Tests whether security principals have an Active Directory extended right.
.DESCRIPTION
    Evaluates direct and inherited allow and deny access rules for the supplied
    principal SIDs. GenericAll and all-extended-rights entries satisfy a specific
    extended-right request.
.PARAMETER DistinguishedName
    Distinguished name of the Active Directory object whose ACL is evaluated.
.PARAMETER PrincipalSids
    SID values for the principal and its transitive security groups.
.PARAMETER ExtendedRight
    GUID of the Active Directory extended right to test.
.OUTPUTS
    System.Boolean
#>
function Test-ADExtendedRight {
    param (
        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName,
        [Parameter(Mandatory = $true)]
        [string[]]$PrincipalSids,
        [Parameter(Mandatory = $true)]
        [Guid]$ExtendedRight
    )

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

        $hasGenericAll = (
            $rule.ActiveDirectoryRights -band
            [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
        ) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
        $hasExtendedRight = (
            $rule.ActiveDirectoryRights -band
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
        ) -eq [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
        $coversRequestedRight = $hasGenericAll -or (
            $hasExtendedRight -and
            ($rule.ObjectType -eq [Guid]::Empty -or $rule.ObjectType -eq $ExtendedRight)
        )

        if (!$coversRequestedRight) {
            continue
        }
        if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
            return $false
        }

        $isAllowed = $true
    }

    return $isAllowed
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
        # status message
        [Parameter(Mandatory = $true)]
        [string]$Message,
        #Severity of the message
        [Parameter (Mandatory = $true)]
        [Validateset('Error', 'Warning', 'Information', 'Debug') ]
        $Severity,
        #Event ID
        [Parameter (Mandatory = $true)]
        [int]$EventID
    )


    # The CSV-like line includes enough context to correlate concurrent executions.
    $LogLine = "$(Get-Date -Format o),$($PID), [$Severity],[$EventID], $Message"
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
$ScriptVersion = "0.1.20261009.2"
$passwordSize = 32
$eventLog = "Application"
$source = "AzureKrbRollOver"
$ChangePasswordExtendedRight = [Guid]'ab721a53-1e2f-11d0-9819-00aa0040529b'
$ResetPasswordExtendedRight = [Guid]'00299570-246d-11d0-a768-00aa006e0529'

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
        $logLine = "$(Get-Date -Format o),$($PID), [Error],[1002], $eventSourceError"
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

$scriptExitCode = 0
$scriptFailureMessage = $null

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
    if ($TGTLifetimeHours -lt $TGTLifetimeHoursMin){
        Write-Log "The TGTLifeTime parameter is lower then $TGTLifeTimeHoursMin. Using $TGTLifeTimeHoursMin" -Severity Warning -EventID 3112
        $TGTLifetimeHours  = $TGTLifeTimeHoursMin
    } elseif ($TGTLifetimeHours -gt $TGTLifetimeHoursMax) {
        Write-Log "The TGTLifeTimeHours exceed the maximum value of $TGTLifeTimeHoursMax." -Severity Warning -EventID 3113
        $TGTLifeTimeHours = $TGTLifeTimeHoursMax
    }
    #endregion
    #region Validate rollover account
    $GlobalCatalogServer = '{0}:{1}' -f (Get-ADDomainController -Discover -Service GlobalCatalog).HostName.Value, $GlobalCatalogPort
    Write-Log -Message "Using $GlobalCatalogServer as Global Catalog server" -Severity Debug -EventID 0

    $accountSearchServer = (Get-ADDomain).PDCEmulator
    $accountLookupValue = $RollOverADAccountName
    $accountLookupProperty = 'SamAccountName'

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
    $gcAzureADSsoAcc.CanonicalName -match "[^/]+" |Out-Null
    $DomainName = $matches[0] 
    $AzureADSsoAcc = Get-ADcomputer -Filter {Name -eq $AzureADSSOAccName} -server $DomainName -Properties pwdLastSet

    # Validate both security contexts before changing the rollover account password.
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if ($currentIdentity.IsSystem) {
        $localComputerDomain = Get-ADDomain -ErrorAction Stop
        $localComputer = Get-ADComputer -Identity "$env:COMPUTERNAME`$" -Server $localComputerDomain.PDCEmulator -Properties SID, tokenGroups -ErrorAction Stop
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
        $currentPrincipal = $currentIdentity.Name
        $currentPrincipalSids = @($currentIdentity.User.Value)
        foreach ($groupSid in $currentIdentity.Groups) {
            $currentPrincipalSids += $groupSid.Value
        }
    }
    $currentPrincipalSids += 'S-1-1-0', 'S-1-5-11'
    $currentPrincipalSids = @($currentPrincipalSids | Select-Object -Unique)

    $canResetRolloverAccount = Test-ADExtendedRight `
        -DistinguishedName $RollOverADUser.DistinguishedName `
        -PrincipalSids $currentPrincipalSids `
        -ExtendedRight $ResetPasswordExtendedRight
    if (!$canResetRolloverAccount) {
        Write-Log -Message "$currentPrincipal does not have Reset Password permission on rollover account $ADUser" -Severity Error -EventID 3102
        throw [System.UnauthorizedAccessException] "$currentPrincipal can not reset the password of rollover account $ADUser"
    }
    Write-Log -Message "$currentPrincipal has Reset Password permission on rollover account $ADUser" -Severity Debug -EventID 0

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

    $missingAzureADSSORights = @()
    if (!(Test-ADExtendedRight -DistinguishedName $AzureADSsoAcc.DistinguishedName -PrincipalSids $rollOverPrincipalSids -ExtendedRight $ChangePasswordExtendedRight)) {
        $missingAzureADSSORights += 'Change Password'
    }
    if (!(Test-ADExtendedRight -DistinguishedName $AzureADSsoAcc.DistinguishedName -PrincipalSids $rollOverPrincipalSids -ExtendedRight $ResetPasswordExtendedRight)) {
        $missingAzureADSSORights += 'Reset Password'
    }
    if ($missingAzureADSSORights.Count -gt 0) {
        $missingRightsText = $missingAzureADSSORights -join ', '
        Write-Log -Message "$ADUser is missing $missingRightsText permission on $AzureADSSOAccName" -Severity Error -EventID 3102
        throw [System.UnauthorizedAccessException] "$ADUser is missing $missingRightsText permission on $AzureADSSOAccName"
    }
    Write-Log -Message "$ADUser has Change Password and Reset Password permissions on $AzureADSSOAccName" -Severity Debug -EventID 0

    $AzureADSsoAccPwdLastSet = [DateTime]::FromFileTime($AzureADSsoAcc.pwdLastSet)
    Write-Log -Message "The AzureADSSOAcc computer account was last password reset at $AzureADSsoAccPwdLastSet" -Severity Debug -EventID 0
    # Avoid invalidating Kerberos tickets that may still be active from the last rollover.
    if ($IgnoreTGTLifetimeCheck){
        Write-Log -Message "Skipping the TGT lifetime check as the IgnoreTGTLifetimeCheck switch is set" -Severity Warning -EventID 3008
    } else {
        if (((Get-Date) - $AzureADSsoAccPwdLastSet).Totalhours -le $TGTLifetimeHours) {
            Write-Log -Message "The AzureADSSOAcc last password reset at $AzureADSsoAccPwdLastSet does not exceed the current TGT lifetime of $TGTLifetimeHours hours" -Severity Warning -EventID 3107
            throw [System.InvalidOperationException] "The AzureADSSOAcc password last set is $AzureADSsoAccPwdLastSet does not expired the TGT lifetime"
        }
    }
    
    $rolloverTarget = "$RollOverADAccountName and $AzureADSSOAccName"
    $rolloverAction = "Reset the rollover account password, synchronize it if enabled, and update the seamless SSO Kerberos key"
    if (-not $PSCmdlet.ShouldProcess($rolloverTarget, $rolloverAction)) {
        Write-Log -Message "Rollover skipped because WhatIf was specified or confirmation was declined" -Severity Information -EventID 3000
        return
    }

    # Reset the synchronized identity before publishing the same secret to seamless SSO.
    Write-Log -Message "Generate a new random password for the Kerberos RollOver Account" -Severity Debug -EventID 0
    $secPwd = New-RandomPassword -length $passwordSize 
    Set-ADAccountPassword -Identity $RollOverADUser.DistinguishedName -Server $rollOverUserDomain.PDCEmulator -NewPassword (ConvertTo-SecureString $secPwd -AsPlainText -Force) -Reset -ErrorAction Stop
    Write-Log -Message "Password for Kerberos RollOver Account $ADUser has been reset" -Severity Debug -EventID 0
    [pscredential]$AdCredential = New-Object System.Management.Automation.PSCredential ($ADuser, (ConvertTo-SecureString $secPwd -AsPlainText -Force))
    Write-Log -Message "Reset Password for Kerberos RollOver Account: $ADUser" -Severity Information -EventID 3001
    if ($StartEntraConnectSync) {
        Write-Log -Message "Starting Entra Connect delta synchronization" -Severity Information -EventID 3002
        Start-ADSyncSyncCycle -PolicyType Delta -ErrorAction Stop
    } else {
        Write-Log -Message "Entra Connect synchronization was not requested" -Severity Debug -EventID 0
    }
    # Verify that the new credential has reached Microsoft Entra ID before updating seamless SSO.
    $syncStartedAt = Get-Date
    $syncDeadline = $syncStartedAt.AddSeconds($AzureSyncTimeoutSeconds)
    $syncAttempt = 0
    $passwordSynchronized = $false
    while (-not $passwordSynchronized -and (Get-Date) -lt $syncDeadline) {
        $syncAttempt++
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
            $syncCheckJob = Start-Job -Credential $AdCredential -ScriptBlock {
                param ($AzureADSSOModule, $RollOverAccountUPN, $secPwd)

                $ErrorActionPreference = 'Stop'
                Import-Module $AzureADSSOModule -Force
                $securePassword = ConvertTo-SecureString $secPwd -AsPlainText -Force
                $cloudCredential = New-Object System.Management.Automation.PSCredential (
                    $RollOverAccountUPN,
                    $securePassword
                )
                New-AzureADSSOAuthenticationContext -CloudCredentials $cloudCredential | Out-Null
            } -ArgumentList $AzureADSSOModule, $RollOverAccountUPN, $secPwd

            $completedJob = Wait-Job -Job $syncCheckJob -Timeout $AzureSyncPollIntervalSeconds
            if (-not $completedJob) {
                Stop-Job -Job $syncCheckJob
                throw [System.TimeoutException] "The password synchronization check exceeded the remaining timeout"
            }
            if ($syncCheckJob.State -ne 'Completed') {
                throw $syncCheckJob.ChildJobs[0].JobStateInfo.Reason
            }
            Receive-Job -Job $syncCheckJob -ErrorAction Stop | Out-Null
            $passwordSynchronized = $true
            Write-Host "The updated password is available in Microsoft Entra ID." -ForegroundColor Green
            Write-Log -Message "The updated password for $RollOverAccountUPN is available in Microsoft Entra ID" -Severity Information -EventID 3003
        }
        catch {
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
        $message = "The updated password for $RollOverAccountUPN was not available in Microsoft Entra ID after five minutes"
        Write-Host $message -ForegroundColor Red
        Write-Log -Message $message -Severity Error -EventID 3114
        throw [System.TimeoutException] $message
    }

    #create temporary file for the new PowerShell process
    $PSShellTempFile = New-TemporaryFile
    #allow $ADUser write access to the temporary file
    $acl = Get-Acl -Path $PSShellTempFile.FullName
    $acl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($ADUser, "FullControl", "Allow")))
    Set-Acl -Path $PSShellTempFile.FullName -AclObject $acl

    #region Update seamless SSO as the rollover account
[pscredential]$AdCredential = New-object System.Management.Automation.PSCredential($ADUser,(ConvertTo-SecureString $secPwd -AsPlainText -Force))
Write-Log -Message "Impersonating user $ADUser to update the Azure Kerberos object" -Severity Debug -EventID 0
# A separate process provides the rollover account's user and device authentication context.
$ADSSResetJob = Start-Job -Credential $AdCredential -ScriptBlock {
    param ($AzureADSSOModule, $RollOverAccountUPN, $ADUser, $secPwd, $VerboseEnabled)
    $verboseParameters = if ($VerboseEnabled) { @{ Verbose = $true } } else { @{} }
    Import-Module $AzureADSSOModule -ErrorAction Stop @verboseParameters
    $secAzPwd = ConvertTo-SecureString -String $secPwd -AsPlainText -Force
    [pscredential]$CredKerbRollOverAzCred = New-Object System.Management.Automation.PSCredential ($RollOverAccountUPN, $secAzPwd);
    [pscredential]$CredKerbRollOverADCred = New-Object System.Management.Automation.PSCredential ($ADUser, $secAzPwd);
    $context = New-AzureADSSOAuthenticationContext -CloudCredentials $CredKerbRollOverAzCred -ErrorAction Stop @verboseParameters
    $update = Update-AzureADSSOForest -PreserveCustomPermissionsOnDesktopSsoAccount -OnPremCredentials $CredKerbRollOverADCred -ErrorAction Stop @verboseParameters
    Write-Output $context, $update
} -ArgumentList $AzureADSSOModule, $RollOverAccountUPN, $ADUser, $secPwd, ($VerbosePreference -eq 'Continue')
Write-Log -Message "Waiting for AzureADSSO Forest update job to complete..." -Severity Debug -EventID 0
try {
    $null = Wait-Job -Job $ADSSResetJob -ErrorAction Stop
    if ($ADSSResetJob.State -ne 'Completed') {
        $jobFailure = $ADSSResetJob.ChildJobs[0].JobStateInfo.Reason
        if ($jobFailure) {
            throw $jobFailure
        }
        throw [System.InvalidOperationException] "AzureADSSO Forest update job ended in state $($ADSSResetJob.State)"
    }

    $JobResult = Receive-Job -Job $ADSSResetJob -ErrorAction Stop
    if ($null -ne $JobResult) {
        Write-Host $JobResult -ForegroundColor Yellow
    }
    Write-Log -Message "AzureADSSO Forest update completed" -Severity Information -EventID 3002
}
finally {
    Remove-Job -Job $ADSSResetJob -Force -ErrorAction Continue
}

    #endregion
    # Read directly from the PDC emulator to avoid stale AD Web Services cache data.
    $PDCEmulator = (Get-ADDomain).PDCEmulator
    $LDAPPath = "LDAP://$PDCEmulator"
    $Searcher = New-Object System.DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($LDAPPath)
    $Searcher.Filter = "(&(objectClass=computer)(sAMAccountName=$AzureADSSOAccName`$))"
    $Searcher.PropertiesToLoad.Add("pwdLastSet") | Out-Null
    # Verify the computer-account password changed during this execution window.
    $Result = $Searcher.FindOne()
    $AzureADSsoAccPwdLastSet = [DateTime]::FromFileTime($Result.Properties.pwdlastset[0])
    Write-Log -Message "The AzureADSSOAcc computer account was last password reset at $AzureADSsoAccPwdLastSet (read from PDC emulator $PDCEmulator)" -Severity Debug -EventID 0
    if ($AzureADSsoAccPwdLastSet -gt (Get-Date).AddMinutes(-15)) {
        Write-Log -Message "The AzureADSSOAcc computer account password was successfully updated at $AzureADSsoAccPwdLastSet" -Severity Debug -EventID 0
    } else {
        Write-Log -Message "The AzureADSSOAcc computer account password was not updated. Last password set is $AzureADSsoAccPwdLastSet" -Severity Error -EventID 3108
        throw [System.InvalidOperationException] "The AzureADSSOAcc computer account password was not updated. Last password set is $AzureADSsoAccPwdLastSet"
    }
    Write-Log -Message "Successfully updated the Azure Kerberos object" -Severity Information -EventID 3004
} 
catch{
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
            Write-log -Message "Access denied during the rollover: $scriptFailureMessage. Ensure $ADUser has the required Active Directory permissions and Microsoft Entra role." -Severity Error -EventID 3102
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
    if ($scriptExitCode -ne 0) {
        Write-Log -Message "Script terminated with error: $scriptFailureMessage" -Severity Warning -EventID 3196
    } else {
        Write-Log -Message "Script completed successfully" -Severity Information -EventID 3006
    }
    Write-Log "=========================================" -Severity Debug -EventID 0
}

exit $scriptExitCode
