# AzKerberosRollOver

This PowerShell script automates the process of resetting the password for the Kerberos RollOver Account and updating the Azure AD SSO Forest with the new password. 

## Overview
It is recommended to change the password of the Azure SSO object every 30 days. This script performs the task in a secure manner and is compatible with the Active Directory Tier Level Model.

## Prerequisites
- A synchronized Active Directory user with the privilege to reset the password on the AzureadSSOACC object with the  Hybrid-Administrator role in Entra.ID.
- The script must run in the context of an identity with the privilege to reset the password of the synchronized user. This can be a technical user, GMSA, or the computer identity of the Entra-Sync computer.

## How It Works
Password Reset: Each time the script runs, it first resets the password of the synchronized user to a randomized password.
Sync Cycle: The script then starts the Entra Cloud-Sync sync cycle.
Azure SSO Password Reset: Once the password is replicated to Entra.ID, the script initiates the reset of the AzureadSSOACC object.

## Usage
To use this script, ensure that the prerequisites are met and execute the script in an environment where the necessary permissions are available.
Create a schedule task to run this script every 30 day

## Script parameter
### AzureADSSOModule 
is the full qualified name of the AzerADSSO.psd1 Powershell module. The default value is C:\:ProgramFiles\Microsoft Azure Active Directory Connect\AzureADSSO.psd1

### RollOverADAccountName 
is the Active Directory SAMAccount name of the user who will be used to reset the password. The default name is AzKrbRollOver

### RollOverAccountUPN
is the Entra UPN of the user. This parameter is only required if the UPN on Active Directory is differentin Entra

### LogPath
is the directory of the debug log. The default value is the %APPDATA%\Local folder of the user who execute the script. If the script runs in System context the dafault value is C:\Windows\system32\config\systemprofile\AppData\Local\azKerberosRollover.ps1.log

### AzureSyncWaitTime
is the time in seconds who long the script will wait for the password sync cycle. The default value is 60 seconds
