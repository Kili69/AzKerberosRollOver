<#PSScriptInfo

.VERSION 0.1.20261007.1
.GUID 2efdf5d8-370e-425c-afad-e5951a84f893

.AUTHOR Andreas Lucas [MSFT]

.COMPANYNAME 
(c) 2021 Microsoft Corporation. All rights reserved.

.COPYRIGHT 

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

Disclaimer:
This sample script is not supported under any Microsoft standard support program or service. 
The sample script is provided AS IS without warranty of any kind. Microsoft further disclaims 
all implied warranties including, without limitation, any implied warranties of merchantability 
or of fitness for a particular purpose. The entire risk arising out of the use or performance of 
the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, 
or anyone else involved in the creation, production, or delivery of the scripts be liable for any 
damages whatsoever (including, without limitation, damages for loss of business profits, business 
interruption, loss of business information, or other pecuniary loss) arising out of the use of or 
inability to use the sample scripts or documentation, even if Microsoft has been advised of the 
possibility of such damages

History
Version 0.1
    Initial version of the script.
Version 0.1.20250501
    Code comments and formatting changes
    New parameter for the log file location
Version 0.1.20250504
    addtional error logging
Version 0.1.20250508
    detect if the script is running in PS-ISE and use the correct log file name
    Parameter AzSyncWaitTime  added validation for 15 to 120 seconds
Version 0.1.20250509
    Parameter RollOverAccountUPN added validation for UPN format
    Parameter AzureADSSOModule added validation for the module path
    Parameter LogPath added validation for the log file path
    Parameter DoNotStartSync added to skip the Azure AD Sync after resetting the password
    Parameter RollOverADAccountName added validation for the Samaccount name of the Kerberos RollOver Account
    If a new line cannot be added the debug log based on a sharing violation, the script will retry 3 times before failing 
Version 0.1.20250808
    Added parameter TGTLifetimeHours to check if the password of the AzureADSSOAccount has been changed within the last x hours. Default value is 10 hours.
    smal bug bugfixes
Version 0.1.20251006
    Parameter validation is now in the code on on the parameter level
    Fixed a bug if the script runs in PSISE the log file name is now correct
    If unsupported parameter values are used the script will now use the default values
    if the tgtlifetime is set to 0 the AzureADSSO check is skipped
    New event IDs for better error handling added. see EventID.md for details
Version 0.1.20251007
    Added more error handling and logging
Version 0.1.20251014
    The script readn the AzureADSSOAcc computer account from the global catalog and read the PwdLastSet property from the AD Object. The AzureADSSOAcc computer account can now located in a different domain then the Azure AD-Sync computer
    Bug-fix in Error handling
Version 0.1.20251107
    The update of the Kerberos SSO object is now executed in a new PowerShell process running under the Kerberos RollOver Account context. This should fix issues if the user is restricted with conditional access policies. 
    If the script is executed as system, the device id will not provide the Azure device information. With the impersonation of the Rollover account the azure login will provide the device ID. Within this information the account can be restricted to a single device.
Version 0.1.20251108
    Minor documentation fix   
Version 0.1.20251110 
    New parameter IgnoreTGTLifetimeCheck to skip the TGT lifetime check. The reset of the Kerberos RollOver Account password will be performed even if the AzureADSSOAcc password last set is within the TGT lifetime.

#>

<#
.SYNOPSIS
    Rolls over the Microsoft Entra seamless SSO Kerberos decryption key.
.DESCRIPTION
    Resets the password of a synchronized Active Directory rollover account and uses
    that identity to update the AzureADSSOAcc computer account through the AzureADSSO
    module.

    The script performs the following operations:
    1. Imports the AzureADSSO, ActiveDirectory, and ADSync modules.
    2. Validates the configured timing values and rollover account.
    3. Locates AzureADSSOAcc through a Global Catalog and checks its pwdLastSet value.
    4. Stops when the previous rollover is still within the configured TGT lifetime,
       unless IgnoreTGTLifetimeCheck is specified.
    5. Generates a new password and resets the on-premises rollover account.
    6. Optionally starts an Entra Connect delta synchronization and waits for replication.
    7. Runs the AzureADSSO forest update in a background job under the rollover account.
    8. Reads pwdLastSet from the PDC emulator to verify that the update succeeded.

    Return codes:
    0x0    Success
    0x3EA  The Windows event source could not be created.

.PARAMETER AzureADSSOModule
    Full path to AzureADSSO.psd1. The default is the standard Microsoft Entra Connect
    installation path under Program Files.
.PARAMETER RollOverADAccountName
    sAMAccountName of the Active Directory account used for the rollover. The account
    must be synchronized to Microsoft Entra ID. The default is AzKrbRollOver.
.PARAMETER RollOverAccountUPN
    Microsoft Entra UPN of the rollover account. When omitted, the value is read from
    the matching Active Directory user.
.PARAMETER LogPath
    Directory in which the debug log is written. A file path is reduced to its parent
    directory. Missing or invalid paths fall back to the current user's LOCALAPPDATA.
.PARAMETER AzureSyncWaitTime
    Number of seconds to wait after starting synchronization. Values are constrained
    to 15 through 900 seconds by the runtime validation. The default is 60 seconds.
.PARAMETER DoNotStartSync
    Skips Start-ADSyncSyncCycle. Use this when synchronization is started separately,
    for example when the account is synchronized by Microsoft Entra Cloud Sync.
.PARAMETER TGTLifetimeHours
    Minimum age, in hours, of the current AzureADSSOAcc password before another
    rollover is allowed. Values are constrained to 0 through 24 hours. A value of 0
    allows an immediate rollover. The default is 10 hours.
.PARAMETER IgnoreTGTLifetimeCheck
    Bypasses the TGT lifetime safety check and forces the rollover workflow to proceed.
.PARAMETER WhatIf
    Validates prerequisites and reports the planned rollover without changing
    passwords, starting synchronization, updating seamless SSO, or writing logs.
.EXAMPLE
    .\azKerberosRollover.ps1 -RollOverAccountUPN 'AzKrbRollOver@contoso.com'

    Performs a rollover with the default account name, timing values, and log location.
.EXAMPLE
    .\azKerberosRollover.ps1 -RollOverADAccountName 'SvcKrbRollover' `
        -RollOverAccountUPN 'SvcKrbRollover@contoso.com' `
        -AzureSyncWaitTime 120 -LogPath 'C:\Logs'

    Uses a custom rollover account, waits two minutes for replication, and writes the
    debug log under C:\Logs.
.EXAMPLE
    .\azKerberosRollover.ps1 -DoNotStartSync -IgnoreTGTLifetimeCheck

    Skips the ADSync trigger and forces the rollover regardless of the previous
    AzureADSSOAcc password age.
.EXAMPLE
    .\azKerberosRollover.ps1 -RollOverAccountUPN 'AzKrbRollOver@contoso.com' -WhatIf

    Validates the environment and reports the planned rollover without making changes.
.NOTES
    Run this script from a Microsoft Entra Connect server in Windows PowerShell with
    permission to create an Application event source, reset the rollover account, read
    Active Directory through the Global Catalog and PDC emulator, and update seamless SSO.

    The generated password is held in process memory only and is never written to the
    debug log.
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
    [Parameter	(Mandatory=$false)]
    [int]$AzureSyncWaitTime = 60,
    [switch]$DoNotStartSync,
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
    Writes a consistently formatted diagnostic record.
.DESCRIPTION
    Writes every message to the debug log and debug stream. Information, warning, and
    error records are also written to the Application event log and displayed in the
    console. Debug records are intentionally file-only.
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
    }
}

#region Script Variables

# Runtime identity and security settings used throughout the workflow.
$ScriptVersion = "0.1.20261007.1"
$passwordSize = 32
$eventLog = "Application"
$source = "AzureKrbRollOver"

# Bounds are enforced at runtime so scheduled invocations cannot use unsafe delays.
$AzSyncWaitTimeMin = 15
$AzSyncWaitTimeMax = 900
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
try {   
    # Event source creation requires administrative rights and must happen before logging.
    if (-not $script:IsWhatIf -and -not [System.Diagnostics.EventLog]::SourceExists($source)) {
        Write-Debug "Creating event source $source in log $eventLog"
        [System.Diagnostics.EventLog]::CreateEventSource($source, $eventLog)
    }
    elseif ($script:IsWhatIf) {
        Write-Debug "WhatIf: Skip Windows event source creation."
    }
}
catch {
    Write-EventLog -logname $eventLog -source "Application" -EventId 0 -EntryType Error -Message "The event source $source could not be created. The script $($MyInvocation.MyCommand) is terminated. Please run the script with elevated privileges or create the Event source $source manually."
    return 0x3EA 
}

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
Write-Debug "Using $LogFile as log file"

# Keep one previous 1 MB log generation to prevent unbounded disk usage.
if (-not $script:IsWhatIf -and (Test-Path $LogFile)){
    if ((Get-Item $LogFile ).Length -gt $MaxLogFileSize){
        if (Test-Path "$LogFile.sav"){
            Remove-Item "$LogFile.sav"
            Write-Debug "Removed old log file $LogFile.sav"
        }
        Rename-Item -Path $LogFile -NewName "$logFile.sav"
    }
} 
#endregion

Write-Log "=========================================" -Severity Debug -EventID 0 
if ($script:IsWhatIf) {
    Write-Log "Script version $ScriptVersion running as $($env:USERNAME) in WhatIf mode; file and event logging are disabled" -Severity Information -EventID 3000
}
else {
    Write-Log "Script version $ScriptVersion running as $($env:USERNAME) Debug log: $LogFile" -Severity Information -EventID 3000
}
Write-Log -Message "The script started with $($MyInvocation.Line) - Process ID $($PID)" -Severity Debug -EventID 0
Write-Log -Message "Current user $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -Severity Debug -EventID 0 
Write-Log -Message "Parameters: AzureADSSOModule: $AzureADSSOModule, RollOverADAccountName: $RollOverADAccountName, RollOverAccountUPN: $RollOverAccountUPN, LogPath: $LogPath, AzureSyncWaitTime: $AzureSyncWaitTime, DoNotStartSync: $DoNotStartSync, TGTLifetimeHours: $TGTLifetimeHours, IgnoreTGTLifetimeCheck: $IgnoreTGTLifetimeCheck, WhatIf: $script:IsWhatIf" -Severity Debug -EventID 0


Try {
    #region Import dependencies
    # AzureADSSO updates seamless SSO, ActiveDirectory performs directory operations,
    # and ADSync optionally starts the synchronization cycle.
    if (!(Get-Module -Name AzureADSSO)){
        Import-Module $AzureADSSOModule -Force -ErrorAction Stop
        Write-Log -Message "Imported AzureADSSO Module" -Severity Debug -EventID 0
    }
    if (!(Get-Module -Name ActiveDirectory)){
        Import-Module ActiveDirectory -Force -ErrorAction Stop
        Write-Log -Message "Imported ActiveDirectory Module" -Severity Debug -EventID 0
    }
    if (!(Get-Module ADSync)){
        Import-Module ADSync -Force -ErrorAction Stop
        Write-Log -Message "Imported ADSync Module" -Severity Debug -EventID 0
    }

    #endregion
    #region Validate runtime inputs
    #region Validate synchronization wait time

    if ($AzureSyncWaitTime -lt $AzSyncWaitTimeMin){
            Write-log -Message "The azure wait time $AzSyncWaitTime seconds to synchronize the password is to low. It must be higher then $AzSyncWaitTimeMin seconds" -Severity Warning -EventID 3100
            $AzSyncWaitTime = $AzSyncWaitTimeMin
    } elseif ($AzureSyncWaitTime -gt $AzSyncWaitTimeMax){
            Write-Log -Message -"the azure wait time $AzSynWaitTime seconds exceed the maximum value of $AzSyncWaitTimeMax seconds" -Severity Warning -EventID 3101
            $AzSyncWaitTime = $AzSyncWaitTimeMax
    }
    #endregion 
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
    if (!(Get-ADuser -Filter {SamAccountName -eq $RollOverADAccountName})){
        Write-Log -Message "can not find $RollOverADAccountName in the current active directory domain" -Severity Error -EventID 3109
        throw [System.ArgumentException] "The Kerberos RollOver Account $RollOverADAccountName does not exist in the current active directory domain"
    }
#endregion
#endregion

    
    # Prefer the directory value so callers only need to supply a UPN when it differs.
    if (!$RollOverAccountUPN) {
        $RollOverAccountUPN = (get-ADuser $RollOverADAccountName).UserPrincipalName
    }
    write-Log -Message "Using $RollOverAccountUPN as UPN for the Kerberos RollOver Account" -Severity Debug -EventID 0

    # AzureADSSOAcc can reside in another domain, so discover it forest-wide first.
    $GlobalCatalogServer = '{0}:{1}' -f (Get-ADDomainController -Discover -Service GlobalCatalog).HostName.Value, $GlobalCatalogPort
    write-Log -Message "Using $GlobalCatalogServer as Global Catalog server" -Severity Debug -EventID 0
    $gcAzureADSsoAcc = Get-ADComputer -Filter {Name -eq $AzureADSSOAccName } -Server "$GlobalCatalogServer" -Properties CanonicalName
    if (!$gcAzureADSsoAcc) {
        Write-Log -Message "AzureADSSOAcc computer account not found in the Global Catalog. Please ensure the Azure AD Connect is installed and configured." -Severity Error -EventID 3106
        throw [System.ArgumentException] "The AzureADSSOAcc computer account was not found in the Global Catalog"
    }
    # CanonicalName begins with the owning DNS domain; query that domain for pwdLastSet.
    $gcAzureADSsoAcc.CanonicalName -match "[^/]+" |Out-Null
    $DomainName = $matches[0] 
    $AzureADSsoAcc = Get-ADcomputer -Filter {Name -eq $AzureADSSOAccName} -server $DomainName -Properties pwdLastSet
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
    Set-ADAccountPassword -Identity $RollOverADAccountName -NewPassword (ConvertTo-SecureString $secPwd -AsPlainText -Force) -Reset -ErrorAction Stop
    Write-Log -Message "Password for Kerberos RollOver Account $RollOverADAccountName has been reset" -Severity Debug -EventID 0
    $DomainNetBiosName = (Get-ADDomain).NetBiosName
    $ADUser = "$DomainNetBiosName\$RollOverADAccountName"
    [pscredential]$AdCredential = New-Object System.Management.Automation.PSCredential ($ADuser, (ConvertTo-SecureString $secPwd -AsPlainText -Force))
    Write-Log -Message "Reset Password for Kerberos RollOver Account: $RollOverADAccountName" -Severity Information -EventID 3001
    if (!$DoNotStartSync) {
        # Start the Azure AD Sync to sync the new password to Azure AD
        Write-Log -Message "Started Azure AD Sync" -Severity Information -EventID 3002
        Start-ADSyncSyncCycle -PolicyType Delta 
    } else {
        Write-Log -Message "Skip starting the Azure AD Sync" -Severity Debug -EventID 0
    }
    # Allow the new credential to reach Microsoft Entra ID before authenticating with it.
    Write-Log -Message "wait $AzureSyncWaitTime secondes for replication to complete..." -Severity Debug -EventID 0
    Start-Sleep -Seconds $AzureSyncWaitTime
    #create temporary file for the new PowerShell process
    $PSShellTempFile = New-TemporaryFile
    #allow $ADUser write access to the temporary file
    $acl = Get-Acl -Path $PSShellTempFile.FullName
    $acl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($ADUser, "FullControl", "Allow")))
    Set-Acl -Path $PSShellTempFile.FullName -AclObject $acl

    #region Update seamless SSO as the rollover account
    $rollOverTask = @"
            Write-host \"Starting AzureADSSO Forest update...\"
            #Import-Module \"$AzureADSSOModule\" -erroraction stop -verbose 
            #`$secAzPwd = ConvertTo-SecureString -String \"$secPwd\" -AsPlainText -Force -Verbose
            #[pscredential]`$CredKerbRollOverAzCred = New-Object System.Management.Automation.PSCredential (\"$RollOverAccountUPN\", `$secAzPwd);
            #[pscredential]`$CredKerbRollOverADCred = New-Object System.Management.Automation.PSCredential (\"$ADUser\", `$secAzPwd);
            #New-AzureADSSOAuthenticationContext -CloudCredentials `$CredKerbRollOverAzCred -Verbose 
            #Update-AzureADSSOForest -PreserveCustomPermissionsOnDesktopSsoAccount -OnPremCredentials `$CredKerbRollOverADCred -Verbose 
"@
[pscredential]$AdCredential = New-object System.Management.Automation.PSCredential($ADUser,(ConvertTo-SecureString $secPwd -AsPlainText -Force))
Write-Log -Message "Impersonating user $ADUser to update the Azure Kerberos object" -Severity Debug -EventID 0
# A separate process provides the rollover account's user and device authentication context.
$ADSSResetJob = Start-Job -Credential $AdCredential -ScriptBlock {
    param ($AzureADSSOModule, $RollOverAccountUPN, $ADUser, $secPwd)
    Import-Module $AzureADSSOModule -erroraction stop -verbose 
    $secAzPwd = ConvertTo-SecureString -String $secPwd -AsPlainText -Force -Verbose
    [pscredential]$CredKerbRollOverAzCred = New-Object System.Management.Automation.PSCredential ($RollOverAccountUPN, $secAzPwd);
    [pscredential]$CredKerbRollOverADCred = New-Object System.Management.Automation.PSCredential ($ADUser, $secAzPwd);
    $context = New-AzureADSSOAuthenticationContext -CloudCredentials $CredKerbRollOverAzCred -Verbose 
    $update = Update-AzureADSSOForest -PreserveCustomPermissionsOnDesktopSsoAccount -OnPremCredentials $CredKerbRollOverADCred -Verbose 
    Write-Output $context, $update
} -ArgumentList $AzureADSSOModule, $RollOverAccountUPN, $ADUser, $secPwd 
Write-Log -Message "Waiting for AzureADSSO Forest update job to complete..." -Severity Debug -EventID 0
Wait-Job -Job $ADSSResetJob 
Write-Log -Message "AzureADSSO Forest update job completed" -Severity Debug -EventID 0
$JobResult = Receive-Job -Job $ADSSResetJob -Keep  
Write-Host $JobResult -ForegroundColor Yellow
Write-Log -Message "AzureADSSO Forest update completed" -Severity Information -EventID 3002
$ADSSResetJob | Remove-Job

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
        Write-Log -Message "The AzureADSSOAcc computer account password was successfully updated at $AzureADSsoAccPwdLastSet" -Severity Information -EventID 3003
    } else {
        Write-Log -Message "The AzureADSSOAcc computer account password was not updated. Last password set is $AzureADSsoAccPwdLastSet" -Severity Error -EventID 3108
        throw [System.InvalidOperationException] "The AzureADSSOAcc computer account password was not updated. Last password set is $AzureADSsoAccPwdLastSet"
    }
    Write-Log -Message "Successfully updated the Azure Kerberos object" -Severity Information -EventID 3004
} 
catch{
    Write-Log -Message "An error occurred:$($_.Exception.Message) $($_.InvocationInfo.PositionMessage)" -Severity Debug -EventID 0
    switch ($_.Exception){
        {$_ -is [System.InvalidOperationException]}{
            Write-Log -Message "Invalid operation $($_)" -Severity Debug -EventID 0
            break
        }
        {$_ -is [System.IO.FileNotFoundException]}{
            if ($Error[0].CategoryInfo.TargetName -like "*AzureADSSO.psd1"){
                Write-log -Message "Take care the script is running on a Microsoft Entra Connect server. Missing $($Error[0].CategoryInfo.TargetName) " -Severity Error -EventID 3111
            } else {
                Write-log -Message "Please install the required PowerShell modules $($Error[0].CategoryInfo.TargetName) " -Severity Error -EventID 3111
            }
            break
        }
        {$_ -is [System.AccessViolationException]}{
            Write-log -Message "Access denied error occured while resetting the password for the Kerberos RollOver Account. Please ensure you have the necessary permissions." -Severity Error -EventID 3102
            break
        }
        {$_ -is [System.ArgumentException]}{
            Write-Log -Message "Invalid argument: $($_)" -Severity Error -EventID 3110
            break
        }
        {$_ -is [System.InvalidOperationException]}{
            Write-Log -Message "A Invalid operation error occurred: $($_)" -Severity Error -EventID 3198
            break
        }
        {$_ -is [System.Management.Automation.CommandNotFoundException]}{
            Write-Log -Message "A required PowerShell command is missing. Please ensure the required PowerShell modules are installed." -Severity Error -EventID 3110
            break
        }
        Default {
            Write-Log -Message "An error occurred: $_" -Severity Error -EventID 3199
        }
    }    
}
finally {
    if ($Error.Count -gt 0) {
        Write-Log -Message "Script terminated with error: $($Error[0].Exception.Message)" -Severity Warning -EventID 3196
    } else {
        Write-Log -Message "Script completed successfully" -Severity Information -EventID 3006
    }
    Write-Log "=========================================" -Severity Debug -EventID 0
}