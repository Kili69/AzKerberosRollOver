<#PSScriptInfo

.VERSION 0.1.20251110

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

.SYNOPSIS
    This script resets the password of the Kerberos RollOver Account and updates the Azure AD SSO Forest with the new password.
.DESCRIPTION
    This script resets the password of the Kerberos RollOver Account and updates the Azure AD SSO Forest with the new password.
    The script uses the AzureADSSO module to perform the update. The script runs as a AD user with privileges to reset the password of the Kerberos RollOver Account.

    Return codes:
    0x0    Success
    0x3EA  Missing powershell modules

.PARAMETER AzureADSSOModule
    The path to the AzureADSSO module. Default is default location of the Azure Active Directory Modules C:\Program Files\Microsoft Azure Active Directory Connect\AzureADSSO.psd1
.PARAMETER RollOverADAccountName
    The Samaccount name of the of the Active Directory Kerberos RollOver Account. Default is AzKrbRollOver. This account must be synchronized to Azure AD
.PARAMETER RollOverAccountUPN
    The UPN of the Kerberos RollOver Account. 
.PARAMETER LogPath
    The path to the log file. Default is $env:LOCALAPPDATA\$($MyInvocation.MyCommand).log. If the path does not exist, the script will use the default location.
.PARAMETER AzureSyncWaitTime
    The wait time in seconds for the Azure AD Sync to complete. Default is 60 seconds. The value must be between 15 and 120 seconds.
    If the value is less than 15 seconds, the script will use the default value of 60 seconds.
.PARAMETER DoNotStartSync
    If this switch is set, the script will not start the Azure AD Sync after resetting the password. The default is to start the sync automatically after resetting the password. This is useful if the account is synchronizes via Azure cloud-Sync
.PARAMETER TGTLifetimeHours
    The lifetime of the Kerberos Ticket Granting Ticket (TGT) in hours. Default is 10 hours. The value must be between 1 and 23 hours.
.PARAMETER IgnoreTGTLifetimeCheck
    If this switch is set, the script will skip the TGT lifetime check and reset the password of the Kerberos RollOver Account even if the AzureADSSOAcc password last set is within the TGT lifetime.
    #>
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
<#
.SYNOPSIS
    Generate a random password of a specified length.
.DESCRIPTION
    This function generates a random password using uppercase letters, lowercase letters, numbers, and special characters.
    The password is generated by selecting random characters from the specified character sets.
    The default length of the password is 12 characters, but this can be changed by passing a different value to the length parameter.
.PARAMETER length
    The length of the password to be generated. The default value is 12 characters.
    This parameter is optional and can be set to any positive integer value.
    If not specified, the function will generate a password of 12 characters.
.EXAMPLE
    New-RandomPassword -length 16
    This command generates a random password of 16 characters.
.EXAMPLE
    New-RandomPassword
    This command generates a random password of the default length (12 characters).
.OUTPUTS
    A string representing the generated random password.
    The password will contain a mix of uppercase letters, lowercase letters, numbers, and special characters.
    The length of the password will be determined by the length parameter.
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
    Write event to the event log and the debug log file
.DESCRIPTION
    This function will write all events to the log file. If the severity is debug the message will only be written to the debug log file
    This function replaced the write-eventlog and write-host cmdlets in this script
.OUTPUTS
    None
.FUNCTIONALITY
    Write event to the log file and event log
.PARAMETER Message
    Is the message body of the event
.PARAMETER Severity
    Is the event severity. Supported severities are: Debug, Information, Warning and Error
.PARAMETER EventID
    Is the event ID logged in the application log
.EXAMPLE
    write-log -Message "My message" - Severity Information -EventID 0
        This will create a new log line in the debug log file, create a eventlog entry in the application log and writes the 
        message parameter to the console
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


    #Format the log message and write it to the log file
    $LogLine = "$(Get-Date -Format o),$($PID), [$Severity],[$EventID], $Message"
    Write-Debug -Message $LogLine
    Add-Content -Path $LogFile -Value $LogLine -Force
    #If the severity is not debug write the even to the event log and format the output
    switch ($Severity) {
        'Error' { 
            Write-Host $Message -ForegroundColor Red
            Add-Content -Path $LogFile -Value $Error[0].ScriptStackTrace 
            Write-EventLog -LogName $eventLog -source $source -EventId $EventID -EntryType Error -Message $Message 
        }
        'Warning' { 
            Write-Host $Message -ForegroundColor Yellow 
            Write-EventLog -LogName $eventLog -source $source -EventId $EventID -EntryType Warning -Message $Message
        }
        'Information' { 
            Write-Host $Message 
            Write-EventLog -LogName $eventLog -source $source -EventId $EventID -EntryType Information -Message $Message
        }
    }
}

#region Script Variables

$ScriptVersion = "0.1.20251110"
$passwordSize = 32
$eventLog = "Application"
$source = "AzureKrbRollOver"
$AzSyncWaitTimeMin = 15
$AzSyncWaitTimeMax = 900
$TGTLifetimeHoursMin = 0
$TGTLifetimeHoursMax = 24
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
    # Check if the source exists; if not, create it
    if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
        Write-Debug "Creating event source $source in log $eventLog"
        [System.Diagnostics.EventLog]::CreateEventSource($source, $eventLog)
    }
}
catch {
    Write-EventLog -logname $eventLog -source "Application" -EventId 0 -EntryType Error -Message "The event source $source could not be created. The script $($MyInvocation.MyCommand) is terminated. Please run the script with elevated privileges or create the Event source $source manually."
    return 0x3EA 
}

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

#Manage the log file size. If the log file is larger than 1MB, rename it to .sav and create a new log file
if (Test-Path $LogFile){
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
Write-Log "Script version $ScriptVersion running as $($env:USERNAME) Debug log: $LogFile" -Severity Information -EventID 3000
Write-Log -Message "The script started with $($MyInvocation.Line) - Process ID $($PID)" -Severity Debug -EventID 0
Write-Log -Message "Current user $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -Severity Debug -EventID 0 
Write-Log -Message "Parameters: AzureADSSOModule: $AzureADSSOModule, RollOverADAccountName: $RollOverADAccountName, RollOverAccountUPN: $RollOverAccountUPN, LogPath: $LogPath, AzureSyncWaitTime: $AzureSyncWaitTime, DoNotStartSync: $DoNotStartSync, TGTLifetimeHours: $TGTLifetimeHours" -Severity Debug -EventID 0


Try {
    #region Import the required modules
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
    #region Validate parameters
    #region Validate the Azure Sync Wait Time. 

    if ($AzureSyncWaitTime -lt $AzSyncWaitTimeMin){
            Write-log -Message "The azure wait time $AzSyncWaitTime seconds to synchronize the password is to low. It must be higher then $AzSyncWaitTimeMin seconds" -Severity Warning -EventID 3100
            $AzSyncWaitTime = $AzSyncWaitTimeMin
    } elseif ($AzureSyncWaitTime -gt $AzSyncWaitTimeMax){
            Write-Log -Message -"the azure wait time $AzSynWaitTime seconds exceed the maximum value of $AzSyncWaitTimeMax seconds" -Severity Warning -EventID 3101
            $AzSyncWaitTime = $AzSyncWaitTimeMax
    }
    #endregion 
    #region validate the TGT lifetime hours
    if ($TGTLifetimeHours -lt $TGTLifetimeHoursMin){
        Write-Log "The TGTLifeTime parameter is lower then $TGTLifeTimeHoursMin. Using $TGTLifeTimeHoursMin" -Severity Warning -EventID 3112
        $TGTLifetimeHours  = $TGTLifeTimeHoursMin
    } elseif ($TGTLifetimeHours -gt $TGTLifetimeHoursMax) {
        Write-Log "The TGTLifeTimeHours exceed the maximum value of $TGTLifeTimeHoursMax." -Severity Warning -EventID 3113
        $TGTLifeTimeHours = $TGTLifeTimeHoursMax
    }
    #endregion
    #region validate user
    if (!(Get-ADuser -Filter {SamAccountName -eq $RollOverADAccountName})){
        Write-Log -Message "can not find $RollOverADAccountName in the current active directory domain" -Severity Error -EventID 3109
        throw [System.ArgumentException] "The Kerberos RollOver Account $RollOverADAccountName does not exist in the current active directory domain"
    }
#endregion
#endregion

    
    #if the UPN match to the active directory UPN read the UPN from the AD account
    if (!$RollOverAccountUPN) {
        $RollOverAccountUPN = (get-ADuser $RollOverADAccountName).UserPrincipalName
    }
    write-Log -Message "Using $RollOverAccountUPN as UPN for the Kerberos RollOver Account" -Severity Debug -EventID 0
    $GlobalCatalogServer = '{0}:{1}' -f (Get-ADDomainController -Discover -Service GlobalCatalog).HostName.Value, $GlobalCatalogPort
    write-Log -Message "Using $GlobalCatalogServer as Global Catalog server" -Severity Debug -EventID 0
    $gcAzureADSsoAcc = Get-ADComputer -Filter {Name -eq $AzureADSSOAccName } -Server "$GlobalCatalogServer" -Properties CanonicalName
    if (!$gcAzureADSsoAcc) {
        Write-Log -Message "AzureADSSOAcc computer account not found in the Global Catalog. Please ensure the Azure AD Connect is installed and configured." -Severity Error -EventID 3106
        throw [System.ArgumentException] "The AzureADSSOAcc computer account was not found in the Global Catalog"
    }
    #extracting domain name from the AzureADSSOAcc computer account
    $gcAzureADSsoAcc.CanonicalName -match "[^/]+" |Out-Null
    $DomainName = $matches[0] 
    $AzureADSsoAcc = Get-ADcomputer -Filter {Name -eq $AzureADSSOAccName} -server $DomainName -Properties pwdLastSet
    $AzureADSsoAccPwdLastSet = [DateTime]::FromFileTime($AzureADSsoAcc.pwdLastSet)
    Write-Log -Message "The AzureADSSOAcc computer account was last password reset at $AzureADSsoAccPwdLastSet" -Severity Debug -EventID 0
    if ($IgnoreTGTLifetimeCheck){
        Write-Log -Message "Skipping the TGT lifetime check as the IgnoreTGTLifetimeCheck switch is set" -Severity Warning -EventID 3008
    } else {
        if (((Get-Date) - $AzureADSsoAccPwdLastSet).Totalhours -le $TGTLifetimeHours) {
            Write-Log -Message "The AzureADSSOAcc last password reset at $AzureADSsoAccPwdLastSet does not exceed the current TGT lifetime of $TGTLifetimeHours hours" -Severity Warning -EventID 3107
            throw [System.InvalidOperationException] "The AzureADSSOAcc password last set is $AzureADSsoAccPwdLastSet does not expired the TGT lifetime"
        }
    }
    
    # Reset the Kerberos RollOver Account Password
        #generate a random password for the Kerberos RollOver Account
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
    #wating for the sync to complete
    Write-Log -Message "wait for replication to complete..." -Severity Debug -EventID 0
    Start-Sleep -Seconds $AzureSyncWaitTime

    
    #region connect to Azure AD with the Kerberos RollOver Account
    $rollOverTask = @"
            Import-Module \"$AzureADSSOModule\" -erroraction stop -verbose;
            `$secAzPwd = ConvertTo-SecureString -String \"$secPwd\" -AsPlainText -Force -Verbose
            [pscredential]`$CredKerbRollOverAzCred = New-Object System.Management.Automation.PSCredential (\"$RollOverAccountUPN\", `$secAzPwd);
            [pscredential]`$CredKerbRollOverADCred = New-Object System.Management.Automation.PSCredential (\"$ADUser\", `$secAzPwd);
            New-AzureADSSOAuthenticationContext -CloudCredentials `$CredKerbRollOverAzCred -Verbose;
            `$result = Update-AzureADSSOForest -PreserveCustomPermissionsOnDesktopSsoAccount -OnPremCredentials `$CredKerbRollOverADCred | out-string
"@
[pscredential]$AdCredential = New-object System.Management.Automation.PSCredential($ADUser,(ConvertTo-SecureString $secPwd -AsPlainText -Force))
Write-Log -Message "Impersonating user $ADUser to update the Azure Kerberos object" -Severity Debug -EventID 0
Start-Process -FilePath powershell.exe -Credential $AdCredential -ArgumentList @(
    "-NoProfile",
    "-Command &{$RollOverTask}"
)
    #endregion

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