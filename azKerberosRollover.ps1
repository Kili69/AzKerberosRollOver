<#PSScriptInfo

.VERSION 0.1.20250509

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
    If this switch is set, the script will not start the Azure AD Sync after resetting the password. This is useful if you want to manually start the sync later.
    The default is to start the sync automatically after resetting the password. This is usefull if the account is synchronises via Azure clud-Sync
.PARAMETER TGTLifetimeHours
    The lifetime of the Kerberos Ticket Granting Ticket (TGT) in hours. Default is 10 hours. The value must be between 1 and 23 hours.
    #>
param(
    [Parameter(Mandatory=$false)]
    [ValidatePattern('^([a-zA-Z]:\\|\\\\[a-zA-Z0-9._-]+\\[a-zA-Z0-9.$_-]+)(\\[a-zA-Z0-9._-]+)*\\AzureADSSO.psd1?$')]
    [string]$AzureADSSOModule = "$env:ProgramFiles\Microsoft Azure Active Directory Connect\AzureADSSO.psd1",
    [Parameter(Mandatory=$false)]
    [ValidatePattern('^[a-zA-Z0-9._-]{1,20}$')]
    [string]$RollOverADAccountName = "AzKrbRollOver",
    [Parameter(Mandatory=$false)]
    [ValidatePattern("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")]
    [string]$RollOverAccountUPN,
    [Parameter(Mandatory=$false)]
    [Validatepattern('^([a-zA-Z]:\\|\\\\[a-zA-Z0-9._-]+\\[a-zA-Z0-9.$_-]+)(\\[a-zA-Z0-9._-]+)*\\?$')]
    [string]$LogPath,
    [Parameter	(Mandatory=$false)][ValidateRange(15, 120)]
    [int]$AzureSyncWaitTime = 60,
    [switch]$DoNotStartSync,
    [ValidateRange(1, 23)]
    [Parameter (Mandatory=$false)]
    [int]$TGTLifetimeHours = 10
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
    $chars += [char[]](33..47)  # Special characters ! " # $ % & ' ( ) * + , - . /

    $password = -join ((1..$length) | ForEach-Object { $chars | Get-Random })
    return ConvertTo-SecureString -String $password -AsPlainText -Force
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
    Add-Content -Path $LogFile -Value $LogLine 
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

$ScriptVersion = "0.1.20250818"
$passwordSize = 32
$eventLog = "Application"
$source = "AzureKrbRollOver"
[int]$MaxLogFileSize = 1048576 #Maximum size of the log file in bytes (1MB)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$AzureADSSOAccName = "AzureADSSOAcc"
#endregion

######################################################
# Main Script Logic 
######################################################

#region Manage log file
try {   

    # Check if the source exists; if not, create it
    if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
        [System.Diagnostics.EventLog]::CreateEventSource($source, $eventLog)
    }
}
catch {
    Write-EventLog -logname $eventLog -source "Application" -EventId 0 -EntryType Error -Message "The event source $source could not be created. The script $($MyInvocation.MyCommand) is terminated. Please run the script with elevated privileges or create the Event source $source manually."
    return 0x3EA 
}

if ($LogPath -eq ""){
    $LogFile = "$($env:LOCALAPPDATA)\$(If($PSISE){$psise.CurrentFile.DisplayName}else{$MyInvocation.MyCommand}).log"
} else {
    if (Test-Path $LogPath){
       $LogFile = "$LogPath\$(If($PSISE){$psise.CurrentFile.DisplayName}else{$MyInvocation.MyCommand}).log" #Name and path of the log file
    } else {
        $LogFile = "$($env:LOCALAPPDATA)\$(If($PSISE){$psise.CurrentFile.DisplayName}else{$MyInvocation.MyCommand}).log" #Name and path of the log file
    }
}

#Manage the log file size. If the log file is larger than 1MB, rename it to .sav and create a new log file
if (Test-Path $LogFile){
    if ((Get-Item $LogFile ).Length -gt $MaxLogFileSize){
        if (Test-Path "$LogFile.sav"){
            Remove-Item "$LogFile.sav"
        }
        Rename-Item -Path $LogFile -NewName "$logFile.sav"
    }
}
#endregion

Write-Log "=========================================" -Severity Debug -EventID 0 
Write-Log "Script version $ScriptVersion running as $($env:USERNAME) Debug log: $LogFile" -Severity Information -EventID 3000
Write-Log -Message "The script started with $($MyInvocation.Line) - Process ID $($PID)" -Severity Debug -EventID 0
Write-Log -Message "Current user $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -Severity Debug -EventID 0 

try {
    #Import the required modules
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
    
    #generate a random password for the Kerberos RollOver Account
    $secPwd = New-RandomPassword -length $passwordSize 
    
    #if the UPN match to the active directory UPN read the UPN from the AD account
    if (!$RollOverAccountUPN) {
        $RollOverAccountUPN = (get-ADuser $RollOverADAccountName).UserPrincipalName
    }
    $GlobalCatalogServer = (Get-ADDomainController -Discover -Service GlobalCatalog).Name
    $AzureADSsoAcc = Get-ADComputer -Filter {Name -eq $AzureADSSOAccName } -Server $GlobalCatalogServer -Properties CanonicalName
    if (!$AzureADSsoAcc) {
        Write-Log -Message "AzureADSSOAcc computer account not found in the Global Catalog. Please ensure the Azure AD Connect is installed and configured." -Severity Error -EventID 3106
        return 0x3EA
    }
    #extracting domain name from the AzureADSSOAcc computer account
    $AzureADSsoAcc.CanonicalName -match "[^/]+" |Out-Null
    $DomainName = $matches[0] 
    $AzureADSsoAcc = Get-ADcomputer -Identity $AzureADSSOAccName -server $DomainName -Properties pwdLastSet
    $AzureADSsoAccPwdLastSet = [DateTime]::FromFileTime($AzureADSsoAcc.pwdLastSet)
    if (((Get-Date) - $AzureADSsoAccPwdLastSet).Totalhours -le $TGTLifetimeHours) {
        Write-Log -Message "The AzureADSSOAcc computer account password has never been set. Please set the password for the AzureADSSOAcc computer account before running this script." -Severity Error -EventID 3107
        return 0x3EA
    }
    
    # Reset the Kerberos RollOver Account Password
    Set-ADAccountPassword -Identity $RollOverADAccountName -NewPassword $secPwd -Reset 
    Write-Log -Message "Reset Password for Kerberos RollOver Account: $RollOverADAccountName" -Severity Information -EventID 3001
    Write-Log -Message "wait for replication to complete..." -Severity Debug -EventID 0
    if (!$DoNotStartSync) {
        # Start the Azure AD Sync to sync the new password to Azure AD
        Start-ADSyncSyncCycle -PolicyType Delta 
        Write-Log -Message "Started Azure AD Sync" -Severity Information -EventID 3002
    } else {
        Write-Log -Message "Skip starting the Azure AD Sync" -Severity Debug -EventID 0
    }
    #wating for the sync to complete
    Start-Sleep -Seconds $AzureSyncWaitTime

    
    #region connect to Azure AD with the Kerberos RollOver Account
    [pscredential]$CredKerbRollOverCred = New-Object System.Management.Automation.PSCredential ("$((Get-ADDomain).NetBIOSName)\$RollOverADAccountName", $secPwd)
    [pscredential]$CredKerbRollOverAzCred = New-Object System.Management.Automation.PSCredential ($RollOverAccountUPN, $secPwd)
    New-AzureADSSOAuthenticationContext -CloudCredentials $CredKerbRollOverAzCred
    Write-Log -Message "Successfully $RollOverAccountUPN authenticated to Azure AD" -Severity Information -EventID 3002
    #endregion

    #Update the Azure AD SSO Forest with the new Kerberos RollOver Account Password
    Update-AzureADSSOForest -OnPremCredentials $CredKerbRollOverCred -PreserveCustomPermissionsOnDesktopSsoAccount 
    Write-Log -Message "Updated Azure AD SSO Forest with new Kerberos RollOver Account Password" -Severity Information -EventID 3003
} 
catch [System.IO.FileNotFoundException] {
    if ($Error[0].CategoryInfo.TargetName -like "*AzureADSSO.psd1"){
        Write-log -Message "$($Error[0].CategoryInfo.TargetName) Take care the script is running on a Microsoft Entra Connect server" -Severity Error -EventID 3100
    } else {
        Write-log -Message "$($Error[0].CategoryInfo.TargetName) Please install the required PowerShell modules" -Severity Error -EventID 3101
    }
} 
catch [System.AccessViolationException] {
    Write-log -Message "Access denied error occured while resetting the password for the Kerberos RollOver Account. Please ensure you have the necessary permissions." -Severity Error -EventID 3102
    return 0x3EC
}
<#catch [Microsoft.Identity.Client.MsalException] {
    switch ($Error[0].CategoryInfo.Reason) {
        "AdalException" {
            Write-Log -Message "Multifactor Authentication enforced for $RollOverAccountUPN" -Severity Error -EventID 3103
            break
          }
        "AdalUserInteractionRequiredException" {
            Write-Log -Message "Multifactor Authentication enforced for $RollOverAccountUPN" -Severity Error -EventID 3104
            break
        }
        "MsalClientException"{
            Write-Log -Message "Password Error enforced for $RollOverAccountUPN" -Severity Error -EventID 3105
            break
        }
        Default {
            Write-Log -Message "An error occurred: $_" -Severity Error -EventID 3198
            break   
        }
    }
    Write-Log -Message $Error[0].Exception -Severity Debug -EventID 0
}#>
catch {
    Write-Log "An error occurred: $_" -Severity Error -EventID 3199  
}
finally {
    if ($Error.Count -gt 0) {
        Write-Log -Message $Error[0].Exception -Severity Debug -EventID 0
    }
    Write-Log "Script finished" -Severity Debug -EventID 0
}