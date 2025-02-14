<#
Script Info 

Author: Andreas Lucas [MSFT]

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
#>
<#
.SYNOPSIS
    This script resets the password for the Kerberos RollOver Account and updates the Azure AD SSO Object 
    with the new password.
.DESCRIPTION
    This script resets the password for the Kerberos RollOver Account and updates the Azure AD SSO Object 
    with the new password. The script ueses a Active Directory Account who will be replicated to the Azure AD.
    The user requires the following permissions:
    Entra ID: Hybrid Administrstor
    Achtvie Directory: 
#>
param(
    [Parameter(Mandatory=$false)]
    [string]$AzureADSSOModule = "$env:ProgramFiles\Microsoft Azure Active Directory Connect\AzureADSSO.psd1",
    [Parameter(Mandatory=$false)]
    [string]$RollOverADAccountName = "AzKrbRollOver",
    [Parameter(Mandatory=$false)]
    [string]$RollOverAccountUPN
)
function New-RandomPassword {
    param (
        [int]$length = 12
    )

    $chars = @()
    $chars += [char[]](65..90)  # Uppercase A-Z
    $chars += [char[]](97..122) # Lowercase a-z
    $chars += [char[]](48..57)  # Numbers 0-9
    $chars += [char[]](33..47)  # Special characters ! " # $ % & ' ( ) * + , - . /

    $password = -join ((1..$length) | ForEach-Object { $chars | Get-Random })
    return $password
}
<#
.SYNOPSIS
    Write status message to the console and to the log file
.DESCRIPTION
    the script status messages are writte to the log file located in the app folder. the the execution date and detailed error messages
    The log file syntax is [current data and time],[severity],[Message]
    On error message the current stack trace will be written to the log file
.PARAMETER Message
    status message written to the console and to the logfile
.PARAMETER Severity
    is the severity of the status message. Values are Error, Warning, Information and Debug. Except Debug all messages will be written 
    to the console
#>
function Write-Log {
    param (
        # status message
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]
        $Message,
        #Severity of the message
        [Parameter (Mandatory = $true)]
        [Validateset('Error', 'Warning', 'Information', 'Debug') ]
        $Severity
    )
    #Format the log message and write it to the log file
    $LogLine = "$(Get-Date -Format "MM/dd/yyyy HH:mm K"), [$Severity], $Message"
    Add-Content -Path $LogFile -Value $LogLine -ErrorAction SilentlyContinue
    switch ($Severity) {
        'Error'   { 
            Write-Host $Message -ForegroundColor Red             
            Add-Content -Path $LogFile -Value $Error[0].ScriptStackTrace   -ErrorAction SilentlyContinue
        }
        'Warning' { Write-Host $Message -ForegroundColor Yellow}
        'Information' { Write-Host $Message }
        }

}
######################################################
# Main Script Logic 
######################################################
#region Manage log file
$ScriptVersion = "20250214"
#$LogDirectory = "$($env:AllUsersProfile)\AzureSSORollOver"
$LogDirectory = "C:\temp"
[int]$MaxLogFileSize = 1048576 #Maximum size of the log file
if (!(Test-Path -Path $LogDirectory)) {
    New-Item -Path $LogDirectory -ItemType Directory
}
$LogFile = "$LogDirectory\$($MyInvocation.MyCommand).log" #Name and path of the log file
#rename existing log files to *.sav if the currentlog file exceed the size of $MaxLogFileSize
if (Test-Path $LogFile){
    if ((Get-Item $LogFile ).Length -gt $MaxLogFileSize){
        if (Test-Path "$LogFile.sav"){
            Remove-Item "$LogFile.sav"
        }
        Rename-Item -Path $LogFile -NewName "$logFile.sav"
    }
}
#endregion
Write-Log "Script version $ScriptVersion running as $($env:USERNAME)" -Severity Information
try {
if (!(Get-Module -Name AzureADSSO)){
    Import-Module $AzureADSSOModule -Force -ErrorAction Stop
    Write-Log -Message "Imported AzureADSSO Module" -Severity Information
}
if (!(Get-Module -Name ActiveDirectory)){
    Import-Module ActiveDirectory -Force -ErrorAction Stop
    Write-Log -Message "Imported ActiveDirectory Module" -Severity Information
}
if (!(Get-Module ADSync)){
    Import-Module ADSync -Force -ErrorAction Stop
    Write-Log -Message "Imported ADSync Module" -Severity Information
}
$secPwd = New-RandomPassword -length 32 | ConvertTo-SecureString -AsPlainText -Force
$secPwd = ConvertTo-SecureString -AsPlainText -String "Password1!" -Force
if (!$RollOverAccountUPN) {
    $RollOverAccountUPN = (get-ADuser $RollOverADAccountName).UserPrincipalName
}
# Reset the Kerberos RollOver Account Password
Set-ADAccountPassword -Identity $RollOverADAccountName -NewPassword $secPwd -Reset 
Write-Log -Message "Reset Password for Kerberos RollOver Account: $RollOverAccountName" -Severity Information
Write-Log -Message "wait for replication to complete..." -Severity Information
Start-ADSyncSyncCycle -PolicyType Delta 
Start-Sleep -Seconds 60
[pscredential]$CredKerbRollOverCred = New-Object System.Management.Automation.PSCredential ("$((Get-ADDomain).NetBIOSName)\$RollOverADAccountName", $secPwd)
[pscredential]$CredKerbRollOverAzCred = New-Object System.Management.Automation.PSCredential ($RollOverAccountUPN, $secPwd)
New-AzureADSSOAuthenticationContext -CloudCredentials $CredKerbRollOverAzCred
Write-Log -Message "Successfully authenticated to Azure AD" -Severity Information
Update-AzureADSSOForest -OnPremCredentials $CredKerbRollOverCred -PreserveCustomPermissionsOnDesktopSsoAccount |Write-Log -Severity Information
Write-Log -Message "Updated Azure AD SSO Forest with new Kerberos RollOver Account Password" -Severity Information
} 
catch [System.IO.FileNotFoundException] {
    Write-log -Message "$($Error[0].CategoryInfo.TargetName) Please install the required PowerShell module" -Severity Error
} 
catch [System.AccessViolationException] {
    Write-log -Message "Access denied error occured while resetting the password for the Kerberos RollOver Account. Please ensure you have the necessary permissions." -Severity Error
}
catch {
    if ($Error[0].CategoryInfo.Reason -eq "AdalClaimChallengeException"){
        Write-Log -Message "Multifactor Authentication enforced for $RollOverAccountUPN" -Severity Error
    } else {
        Write-Log "An error occurred: $_" -Severity Error
    }
}
