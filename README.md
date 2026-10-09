<div align="center">
  <img src="docs/assets/azkerberosrollover-logo.png" alt="AzKerberosRollOver logo" width="280">

  # AzKerberosRollOver

  **Automated Kerberos key rollover for Microsoft Entra seamless single sign-on**

  [![PowerShell](https://img.shields.io/badge/PowerShell-5.1-5391FE?logo=powershell&logoColor=white)](https://learn.microsoft.com/powershell/)
  [![Platform](https://img.shields.io/badge/platform-Windows-0078D4?logo=windows&logoColor=white)](https://www.microsoft.com/windows)
  [![Microsoft Entra](https://img.shields.io/badge/Microsoft-Entra_ID-5C2D91?logo=microsoft&logoColor=white)](https://www.microsoft.com/security/business/identity-access/microsoft-entra-id)
  [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

  [Overview](#overview) · [The problem](#the-problem) · [The solution](#the-solution) · [Installation](#installation) · [Script parameters](#script-parameters) · [Monitoring](#monitoring) · [Troubleshooting](#troubleshooting) · [Contributors](#contributors) · [Developer information](#developer-information) · [License](#license)
</div>

---

## Overview

AzKerberosRollOver automates the rollover of the Microsoft Entra seamless single sign-on Kerberos decryption key. The PowerShell script resets a synchronized Active Directory rollover account and updates the `AzureADSSOAcc` computer account through the Microsoft `AzureADSSO` module.

<p>
  🛡️ Securely manages the Kerberos decryption key for Microsoft Entra seamless SSO.<br>
  🔎 Automatically discovers <code>AzureADSSOAcc</code> across the forest.<br>
  🔑 Automatically resets the password for the rollover account.<br>
  👤 Runs the seamless SSO update under the rollover account's identity.<br>
  ✅ Verifies the update directly against the PDC emulator.<br>
  📝 Writes diagnostics to the Windows Application event log.
</p>

## The problem

Microsoft Entra seamless SSO uses the `AzureADSSOAcc` computer account in Active Directory to encrypt and decrypt Kerberos tickets. The password of this account acts as the Kerberos decryption key. If the key is compromised and not rotated regularly, it can remain useful to an attacker for an extended period.

[Microsoft recommends rolling over this key at least every 30 days](https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sso-faq#how-can-i-roll-over-the-kerberos-decryption-key-of-the-%60azureadsso%60-computer-account).

Microsoft documents the rollover as an interactive administrative process that requires a Microsoft Entra administrator to provide credentials and run the seamless SSO update manually.

## The solution

AzKerberosRollOver is a PowerShell script that automates the password and Kerberos decryption key update process described in the [Microsoft seamless SSO documentation](https://learn.microsoft.com/de-de/entra/identity/hybrid/connect/how-to-connect-sso-faq#wie-kann-ich-den-kerberos-entschl-sselungsschl-ssel-des--azureadsso--computerkontos-erneuern-).

The Microsoft procedure is designed as an interactive administrative workflow. An administrator imports the required modules, authenticates with Microsoft Entra and on-premises credentials, and runs `Update-AzureADSSOForest` for the target forest. AzKerberosRollOver turns these manual steps into a repeatable workflow that can also be scheduled and monitored.

The script uses a synchronized hybrid identity as its rollover account. This account requires the delegated Active Directory permissions needed to update `AzureADSSOAcc` and the **Hybrid Identity Administrator** role in Microsoft Entra ID. During each run, the script generates a new strong random password for the rollover account, synchronizes the credential, and uses the account to run `Update-AzureADSSOForest`.

> [!IMPORTANT]
> No password for the rollover account is stored on disk or written to a log. The randomly generated password exists only in process memory while the script is running and is discarded when the process ends.

### Workflow overview

```mermaid
flowchart LR
    Check[Check whether a rollover is due]
    Reset[Set a strong random password<br/>for the rollover account]
    Sync[Wait for password synchronization]
    Update[Run Update-AzureADSSOForest]
    Complete([AzureADSSOAcc key rollover complete])

    Check --> Reset --> Sync --> Update --> Complete
```

### azKerberosRollover

The script first loads the required PowerShell modules and checks the configuration, the rollover account, and the timing settings. It then locates the `AzureADSSOAcc` computer account through a Global Catalog and checks when its password was last changed. If Kerberos tickets created with the current key may still be valid, the script stops before making any changes.

When a rollover is safe, the script generates a new 32-character password and assigns it to the synchronized rollover account. It can then start an Entra Connect delta synchronization and checks every 30 seconds whether the new credential is available in Microsoft Entra ID. If authentication succeeds within five minutes, the synchronized account is used to run `Update-AzureADSSOForest` in a background job.

Finally, the script reads `pwdLastSet` directly from the PDC emulator to verify that the password of `AzureADSSOAcc` was updated successfully. The result is recorded in the local log and the Windows Application event log so that scheduled executions can be monitored.

## Installation

### Prerequisites

#### 👤 Worker account

Create a dedicated Active Directory user account to act as the worker account for the rollover process. The account:

- Must be synchronized to Microsoft Entra ID.
- Must have a permanent assignment of the Microsoft Entra **Hybrid Identity Administrator** role.

#### 🖥️ Entra Connect server

#### 🧩 PowerShell modules

The following PowerShell modules must be available on the Microsoft Entra Connect server:

- `AzureADSSO`
- `ActiveDirectory`
- `ADSync`

> [!NOTE]
> The default path of the `AzureADSSO` module is:
> `C:\Program Files\Microsoft Azure Active Directory Connect\AzureADSSO.psd1`

### Prepare the worker account

The worker account must be able to change and reset the password of the `AzureADSSOAcc` computer object. Delegate only the required **Change Password** and **Reset Password** extended rights instead of granting broad administrative permissions.

Run the following commands once with an account that is allowed to modify permissions on the `AzureADSSOAcc` object:

```powershell
Import-Module ActiveDirectory

$workerAccount = Get-ADUser -Identity 'AzKrbRollOver'
$azureAdSsoAccount = Get-ADComputer -Identity 'AzureADSSOAcc'
$aclPath = "AD:\$($azureAdSsoAccount.DistinguishedName)"
$acl = Get-Acl -Path $aclPath

$extendedRightGuids = @(
    [Guid]'ab721a53-1e2f-11d0-9819-00aa0040529b' # Change Password
    [Guid]'00299570-246d-11d0-a768-00aa006e0529' # Reset Password
)

foreach ($extendedRightGuid in $extendedRightGuids) {
    $accessRule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
        $workerAccount.SID,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $extendedRightGuid
    )
    $acl.AddAccessRule($accessRule)
}

Set-Acl -Path $aclPath -AclObject $acl
```

Replace `AzKrbRollOver` if a different worker account name is used. The two GUIDs identify the built-in Active Directory extended rights for changing and resetting a password.

Verify the delegated permissions:

```powershell
$domainNetBiosName = (Get-ADDomain).NetBIOSName
$workerPrincipal = "$domainNetBiosName\$($workerAccount.SamAccountName)"

(Get-Acl -Path $aclPath).Access |
    Where-Object {
        $_.IdentityReference -eq $workerPrincipal -and
        $_.ObjectType -in $extendedRightGuids
    } |
    Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType, ObjectType
```

### Prepare the Entra Connect server

When the scheduled task runs as `SYSTEM`, it uses the computer account of the Entra Connect server to reset the worker account password. This computer account therefore requires the **Change Password** and **Reset Password** extended rights on the worker account object.

Password-management permissions on the worker account should not be inherited. Disable inheritance on the worker account and restrict password changes and resets to:

- The computer account of the Entra Connect server.
- The built-in **Domain Admins** group.

> [!CAUTION]
> Changing an Active Directory ACL can affect account administration. Test the commands in a non-production environment first and review the resulting ACL before using the worker account. The example preserves other inherited permissions as explicit entries, but removes password-management and generic extended-right entries from all principals except the Entra Connect server and Domain Admins.

Run the following commands once with an account that is allowed to modify permissions on the worker account:

```powershell
Import-Module ActiveDirectory

$domain = Get-ADDomain
$workerAccount = Get-ADUser -Identity 'AzKrbRollOver'
$entraConnectServer = Get-ADComputer -Identity $env:COMPUTERNAME
$domainAdmins = Get-ADGroup -Identity "$($domain.DomainSID)-512"
$aclPath = "AD:\$($workerAccount.DistinguishedName)"
$acl = Get-Acl -Path $aclPath

$extendedRightGuids = @(
    [Guid]'ab721a53-1e2f-11d0-9819-00aa0040529b' # Change Password
    [Guid]'00299570-246d-11d0-a768-00aa006e0529' # Reset Password
)

$allowedSids = @(
    $entraConnectServer.SID.Value
    $domainAdmins.SID.Value
)

# Disable inheritance while preserving existing inherited entries as explicit entries.
$acl.SetAccessRuleProtection($true, $true)

$rulesToRemove = @(
    $acl.Access | Where-Object {
        $identitySid = $_.IdentityReference.Translate(
            [System.Security.Principal.SecurityIdentifier]
        ).Value

        $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
        ($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -and
        ($_.ObjectType -eq [Guid]::Empty -or $_.ObjectType -in $extendedRightGuids) -and
        $identitySid -notin $allowedSids
    }
)

foreach ($rule in $rulesToRemove) {
    [void]$acl.RemoveAccessRuleSpecific($rule)
}

foreach ($principal in @($entraConnectServer, $domainAdmins)) {
    foreach ($extendedRightGuid in $extendedRightGuids) {
        $accessRule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
            $principal.SID,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow,
            $extendedRightGuid
        )
        [void]$acl.AddAccessRule($accessRule)
    }
}

Set-Acl -Path $aclPath -AclObject $acl
```

Run the commands on the Entra Connect server or replace `$env:COMPUTERNAME` with the name of that server. Replace `AzKrbRollOver` if a different worker account name is used.

Verify the delegated permissions:

```powershell
$domainNetBiosName = $domain.NetBIOSName
$serverPrincipal = "$domainNetBiosName\$($entraConnectServer.SamAccountName)"
$domainAdminsPrincipal = "$domainNetBiosName\$($domainAdmins.SamAccountName)"

(Get-Acl -Path $aclPath).Access |
    Where-Object {
        $_.IdentityReference -in @($serverPrincipal, $domainAdminsPrincipal) -and
        $_.ObjectType -in $extendedRightGuids
    } |
    Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType, ObjectType
```

> [!NOTE]
> If the scheduled task runs under a dedicated service account instead of `SYSTEM`, delegate these rights to that service account rather than to the Entra Connect server computer account.

### Copy the script

Download or clone the repository on the Entra Connect server. Open an elevated Windows PowerShell session in the repository directory and copy the script to a permanent location. A directory under `Program Files` is recommended:

```powershell
$installPath = Join-Path $env:ProgramFiles 'AzKerberosRollOver'

New-Item -Path $installPath -ItemType Directory -Force | Out-Null
Copy-Item -LiteralPath '.\azKerberosRollover.ps1' -Destination $installPath -Force
```

The resulting script path is:

```text
C:\Program Files\AzKerberosRollOver\azKerberosRollover.ps1
```

> [!NOTE]
> Keep the script in a protected directory that cannot be modified by standard users. Update the installed copy when deploying a newer version.

### Create the scheduled task

Create a daily scheduled task that runs the script as `SYSTEM`. The task passes only the required `RollOverAccountUPN` script parameter.

Run the following commands from an elevated Windows PowerShell session and replace the example UPN with the UPN of the synchronized worker account:

```powershell
$scriptPath = Join-Path $env:ProgramFiles 'AzKerberosRollOver\azKerberosRollover.ps1'
$rollOverAccountUpn = 'AzKrbRollOver@contoso.com'

$action = New-ScheduledTaskAction `
    -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -RollOverAccountUPN `"$rollOverAccountUpn`""

$trigger = New-ScheduledTaskTrigger -Daily -At '02:00'
$principal = New-ScheduledTaskPrincipal `
    -UserId 'SYSTEM' `
    -LogonType ServiceAccount `
    -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable

Register-ScheduledTask `
    -TaskName 'AzKerberosRollOver' `
    -Description 'Daily rollover check for the Microsoft Entra seamless SSO Kerberos key.' `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Force
```

The task runs every day at 02:00. Change the value passed to `-At` if a different execution time is required.

### Validate the installation

Open an elevated Windows PowerShell session and preview the rollover without making changes:

```powershell
& "$env:ProgramFiles\AzKerberosRollOver\azKerberosRollover.ps1" `
    -RollOverAccountUPN 'AzKrbRollOver@contoso.com' `
    -WhatIf
```

> [!TIP]
> Start with `-WhatIf` to validate the account, modules, directory access, and timing requirements before the first rollover.

### Run the rollover

```powershell
& "$env:ProgramFiles\AzKerberosRollOver\azKerberosRollover.ps1" `
    -RollOverAccountUPN 'AzKrbRollOver@contoso.com'
```

## Script parameters

The following examples use the installed script path:

```powershell
$scriptPath = "$env:ProgramFiles\AzKerberosRollOver\azKerberosRollover.ps1"
```

### `-AzureADSSOModule`

Specifies the full path to `AzureADSSO.psd1`. The default is the standard Microsoft Entra Connect installation path:

```text
C:\Program Files\Microsoft Azure Active Directory Connect\AzureADSSO.psd1
```

Use a custom module location:

```powershell
& $scriptPath `
    -RollOverAccountUPN 'AzKrbRollOver@contoso.com' `
    -AzureADSSOModule 'D:\EntraConnect\AzureADSSO.psd1'
```

### `-RollOverADAccountName`

Specifies the Active Directory `sAMAccountName` of the synchronized worker account. The default is `AzKrbRollOver`.

Use a worker account with a different `sAMAccountName`:

```powershell
& $scriptPath `
    -RollOverADAccountName 'SvcKrbRollover' `
    -RollOverAccountUPN 'SvcKrbRollover@contoso.com'
```

### `-RollOverAccountUPN`

Specifies the Microsoft Entra UPN of the worker account. When this parameter is omitted, the script reads the UPN from the matching Active Directory user. Supplying it explicitly is recommended for scheduled execution.

```powershell
& $scriptPath `
    -RollOverAccountUPN 'AzKrbRollOver@contoso.com'
```

### `-LogPath`

Specifies the directory for `azKerberosRollover.ps1.log`. When omitted or invalid, the script uses `%LOCALAPPDATA%`. If a file path is supplied, the script uses its parent directory.

Write the log to `C:\Logs`:

```powershell
& $scriptPath `
    -RollOverAccountUPN 'AzKrbRollOver@contoso.com' `
    -LogPath 'C:\Logs'
```

### `-DoNotStartSync`

Prevents the script from calling `Start-ADSyncSyncCycle`. Use this switch when password synchronization is triggered or managed separately.

```powershell
& $scriptPath `
    -RollOverAccountUPN 'AzKrbRollOver@contoso.com' `
    -DoNotStartSync
```

### `-TGTLifetimeHours`

Specifies the minimum age of the current `AzureADSSOAcc` password before another rollover is allowed. The default is `10` hours. Values are limited to `0` through `24`; a value of `0` allows an immediate rollover.

Require the current key to be at least 12 hours old:

```powershell
& $scriptPath `
    -RollOverAccountUPN 'AzKrbRollOver@contoso.com' `
    -TGTLifetimeHours 12
```

### `-IgnoreTGTLifetimeCheck`

Bypasses the TGT lifetime safety check and continues regardless of the previous `AzureADSSOAcc` password update time.

```powershell
& $scriptPath `
    -RollOverAccountUPN 'AzKrbRollOver@contoso.com' `
    -IgnoreTGTLifetimeCheck
```

> [!CAUTION]
> Use `-IgnoreTGTLifetimeCheck` only after assessing the risk. Kerberos tickets issued with the previous key may still be active.

### `-WhatIf`

Validates the prerequisites and reports the planned rollover without changing passwords, starting synchronization, updating seamless SSO, or writing logs.

```powershell
& $scriptPath `
    -RollOverAccountUPN 'AzKrbRollOver@contoso.com' `
    -WhatIf
```

For complete PowerShell help, run:

```powershell
Get-Help $scriptPath -Full
```

## Monitoring

The script writes detailed execution information to:

- `<LogPath>\azKerberosRollover.ps1.log`
- The Windows Application event log with the source `AzureKrbRollOver`

When `-LogPath` is not specified, the log file is written to `%LOCALAPPDATA%` of the account running the script. The active log is rotated to a single `.sav` file when it exceeds 1 MB.

Read the latest entries from a configured log directory:

```powershell
Get-Content 'C:\Logs\azKerberosRollover.ps1.log' -Tail 50
```

Read recent Windows events generated by the script:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'AzureKrbRollOver'
} -MaxEvents 20
```

See the [event ID reference](EventID.md) for the events, severities, and messages written by the script.

> [!NOTE]
> `-WhatIf` does not create or modify log files, event sources, or Windows events.

## Troubleshooting

Start troubleshooting by reviewing the local log file and the Windows Application events. Use the [event ID reference](EventID.md) to identify the failed stage and its meaning.

### Exit codes

The scheduled PowerShell process returns the following exit codes to Task Scheduler:

| Exit code | Decimal | Meaning | Recommended action |
| --- | ---: | --- | --- |
| `0x0` | `0` | The script completed successfully, or `-WhatIf` completed without making changes. | No action is required. |
| `0x1` | `1` | The rollover workflow terminated with an error. | Review the local log and Windows Application events to identify the failed operation. |
| `0x3EA` | `1002` | The `AzureKrbRollOver` Windows event source could not be created. | Run the task with administrative rights or create the event source before the next run. |
| `0x3EB` | `1003` | The updated worker account password was not available in Microsoft Entra ID after five minutes. | Check Entra Connect synchronization health and password hash synchronization before retrying. |

The most recent result is displayed in the **Last Run Result** column in Task Scheduler. A value other than `0x0` indicates that the execution requires investigation.

### Event errors

The following errors can be written to the Windows Application event log. See the [event ID reference](EventID.md) for the complete event catalog.

| Event ID | Error | Recommended action |
| --- | --- | --- |
| `3102` | The worker account password could not be reset because access was denied. | Verify that the task runs as `SYSTEM` and that the Entra Connect server computer account has **Change Password** and **Reset Password** rights on the worker account. |
| `3103` | Multifactor authentication is enforced for the worker account. | Review the authentication requirements and Conditional Access policies applied to the worker account. |
| `3104` | Authentication of the worker account was blocked by multifactor requirements. | Confirm that the account and device context satisfy the applicable Conditional Access policies. |
| `3105` | The new worker account password is not available in Microsoft Entra ID. | Check Entra Connect synchronization health, password hash synchronization, and the worker account's synchronization scope. |
| `3106` | `AzureADSSOAcc` could not be found through the Global Catalog. | Verify that seamless SSO is configured and that the Entra Connect server can contact a Global Catalog. |
| `3108` | The `AzureADSSOAcc` password was not updated by the rollover. | Review the job output and authentication events, then confirm connectivity to the PDC emulator before retrying. |
| `3109` | The configured worker account could not be found in Active Directory. | Verify `-RollOverADAccountName` and confirm that the account exists in the current domain. |
| `3110` | An invalid argument was supplied or a required PowerShell command is unavailable. | Review the supplied parameters and confirm that all required modules and commands are installed. |
| `3111` | A required PowerShell module could not be loaded. | Confirm that `AzureADSSO`, `ActiveDirectory`, and `ADSync` are installed and verify `-AzureADSSOModule`. |
| `3114` | The worker account password was not synchronized to Microsoft Entra ID within five minutes. | Check Entra Connect synchronization health, password hash synchronization, and the worker account's synchronization scope. |
| `3197` | The script could not write to its log file. | Verify that the log directory exists, has free space, and grants write access to the task identity. |
| `3198` | An invalid operation or authentication operation failed. | Review the detailed local log and Microsoft Entra sign-in logs for the underlying exception. |
| `3199` | An unexpected error occurred. | Review the detailed local log and Windows event message for the exception and failed operation. |

Confirm that all required PowerShell modules are available:

```powershell
Get-Module -ListAvailable AzureADSSO, ActiveDirectory, ADSync
```

Run the read-only validation path:

```powershell
& "$env:ProgramFiles\AzKerberosRollOver\azKerberosRollover.ps1" `
    -RollOverAccountUPN 'AzKrbRollOver@contoso.com' `
    -WhatIf
```

Display the complete built-in help:

```powershell
Get-Help "$env:ProgramFiles\AzKerberosRollOver\azKerberosRollover.ps1" -Full
```

## Contributors

AzKerberosRollOver is maintained by [Andreas Lucas (Kili69)](https://github.com/Kili69).

Contributions, bug reports, and improvement suggestions are welcome through the [GitHub repository](https://github.com/Kili69/AzKerberosRollOver).

## Developer information

Repository setup, implementation details, versioning, Git hooks, contribution guidance, and validation procedures are documented in the [developer guide](developer.md).

## License

AzKerberosRollOver is licensed under the [MIT License](LICENSE).
