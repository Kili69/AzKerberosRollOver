#Requires -Version 5.1

<#
.SYNOPSIS
    Configures the Active Directory permissions required by AzKerberosRollOver.
.DESCRIPTION
    Replaces the rollover user DACL with the current AdminSDHolder DACL from its
    domain, disables permission inheritance, and grants the Entra Connect computer
    account Reset Password on the rollover user.

    The rollover user also receives Change Password and Reset Password extended
    rights on the AzureADSSOAcc computer account. When the scheduled task runs as
    local SYSTEM, Active Directory authorizes it as the Entra Connect computer account.
.PARAMETER RollOverADAccountName
    Rollover user as sAMAccountName, UPN, or DOMAIN\sAMAccountName.
.PARAMETER EntraConnectComputerName
    Entra Connect computer as computer name, DNS host name, or
    DOMAIN\computerName. The default is the local computer.
.PARAMETER AzureADSSOAccountName
    Name of the seamless SSO computer account. The default is AzureADSSOAcc.
.PARAMETER Force
    Suppresses confirmation prompts. This parameter does not override WhatIf.
.EXAMPLE
    .\Set-AzKerberosRolloverPermissions.ps1 `
        -RollOverADAccountName 'Svc-KerberosRollOver@contoso.com'

    Protects the rollover user ACL and grants the permissions required for SYSTEM
    scheduled-task execution on the local Entra Connect server.
.EXAMPLE
    .\Set-AzKerberosRolloverPermissions.ps1 `
        -RollOverADAccountName 'CONTOSO\Svc-KerberosRollOver' `
        -EntraConnectComputerName 'CONTOSO\ENTRACONNECT01' `
        -WhatIf

    Resolves all objects and previews the ACL changes without applying them.
.EXAMPLE
    .\Set-AzKerberosRolloverPermissions.ps1 `
        -RollOverADAccountName 'CONTOSO\Svc-KerberosRollOver' `
        -Force

    Applies the required ACLs without confirmation prompts.
.NOTES
    Run this script with an account that can modify the ACLs of both target objects.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$RollOverADAccountName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$EntraConnectComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AzureADSSOAccountName = 'AzureADSSOAcc',

    [switch]$Force
)

$ChangePasswordExtendedRight = [Guid]'ab721a53-1e2f-11d0-9819-00aa0040529b'
$ResetPasswordExtendedRight = [Guid]'00299570-246d-11d0-a768-00aa006e0529'
$GlobalCatalogPort = 3268

function Resolve-ADUserAccount {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Identity,
        [Parameter(Mandatory = $true)]
        [string]$GlobalCatalogServer
    )

    $searchServer = (Get-ADDomain -ErrorAction Stop).PDCEmulator
    $lookupValue = $Identity
    $lookupProperty = 'SamAccountName'

    if ($Identity -match '^(?<Domain>[^\\]+)\\(?<Name>[^\\]+)$') {
        $domain = Get-ADDomain -Identity $Matches.Domain -ErrorAction Stop
        $searchServer = $domain.PDCEmulator
        $lookupValue = $Matches.Name
    }
    elseif ($Identity -like '*@*') {
        $searchServer = $GlobalCatalogServer
        $lookupProperty = 'UserPrincipalName'
    }

    if ($lookupProperty -eq 'UserPrincipalName') {
        $resolvedUsers = @(Get-ADUser -Filter {UserPrincipalName -eq $lookupValue} -Server $searchServer -Properties CanonicalName -ErrorAction Stop)
    }
    else {
        $resolvedUsers = @(Get-ADUser -Filter {SamAccountName -eq $lookupValue} -Server $searchServer -Properties CanonicalName -ErrorAction Stop)
    }

    if ($resolvedUsers.Count -eq 0) {
        throw [System.ArgumentException] "Active Directory user $Identity was not found"
    }
    if ($resolvedUsers.Count -gt 1) {
        throw [System.ArgumentException] "Active Directory user $Identity is not unique"
    }

    $domainDnsName = ($resolvedUsers[0].CanonicalName -split '/', 2)[0]
    $domain = Get-ADDomain -Identity $domainDnsName -ErrorAction Stop
    $user = Get-ADUser -Identity $resolvedUsers[0].DistinguishedName -Server $domain.PDCEmulator -Properties SID, SamAccountName, UserPrincipalName -ErrorAction Stop

    return [pscustomobject]@{
        Object = $user
        Domain = $domain
    }
}

function Resolve-ADComputerAccount {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Identity,
        [Parameter(Mandatory = $true)]
        [string]$GlobalCatalogServer,
        [switch]$ForestWide
    )

    $searchServer = (Get-ADDomain -ErrorAction Stop).PDCEmulator
    $lookupValue = $Identity

    if ($Identity -match '^(?<Domain>[^\\]+)\\(?<Name>[^\\]+)$') {
        $domain = Get-ADDomain -Identity $Matches.Domain -ErrorAction Stop
        $searchServer = $domain.PDCEmulator
        $lookupValue = $Matches.Name
    }
    elseif ($ForestWide) {
        $searchServer = $GlobalCatalogServer
    }

    $lookupValue = $lookupValue.TrimEnd('$')
    $samAccountName = "$lookupValue`$"
    $resolvedComputers = @(Get-ADComputer -Filter {
        Name -eq $lookupValue -or
        DNSHostName -eq $lookupValue -or
        SamAccountName -eq $samAccountName
    } -Server $searchServer -Properties CanonicalName -ErrorAction Stop)

    if ($resolvedComputers.Count -eq 0) {
        throw [System.ArgumentException] "Active Directory computer $Identity was not found"
    }
    if ($resolvedComputers.Count -gt 1) {
        throw [System.ArgumentException] "Active Directory computer $Identity is not unique"
    }

    $domainDnsName = ($resolvedComputers[0].CanonicalName -split '/', 2)[0]
    $domain = Get-ADDomain -Identity $domainDnsName -ErrorAction Stop
    $computer = Get-ADComputer -Identity $resolvedComputers[0].DistinguishedName -Server $domain.PDCEmulator -Properties SID, DNSHostName, SamAccountName -ErrorAction Stop

    return [pscustomobject]@{
        Object = $computer
        Domain = $domain
    }
}

function Set-ADProtectedRolloverUserAcl {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TargetDistinguishedName,
        [Parameter(Mandatory = $true)]
        [string]$AdminSDHolderDistinguishedName,
        [Parameter(Mandatory = $true)]
        [string]$TargetServer,
        [Parameter(Mandatory = $true)]
        [System.Security.Principal.SecurityIdentifier]$ComputerSid,
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        [Parameter(Mandatory = $true)]
        [string]$TargetName,
        [switch]$Force
    )

    $targetEntry = New-Object System.DirectoryServices.DirectoryEntry(
        "LDAP://$TargetServer/$TargetDistinguishedName"
    )
    $adminSDHolderEntry = New-Object System.DirectoryServices.DirectoryEntry(
        "LDAP://$TargetServer/$AdminSDHolderDistinguishedName"
    )

    try {
        $targetAcl = $targetEntry.ObjectSecurity
        $currentDacl = $targetAcl.GetSecurityDescriptorSddlForm(
            [System.Security.AccessControl.AccessControlSections]::Access
        )
        $adminSDHolderDacl = $adminSDHolderEntry.ObjectSecurity.GetSecurityDescriptorSddlForm(
            [System.Security.AccessControl.AccessControlSections]::Access
        )

        $targetAcl.SetSecurityDescriptorSddlForm(
            $adminSDHolderDacl,
            [System.Security.AccessControl.AccessControlSections]::Access
        )
        $targetAcl.SetAccessRuleProtection($true, $false)

        $resetPasswordRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $ComputerSid,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow,
            $ResetPasswordExtendedRight
        )
        [void]$targetAcl.AddAccessRule($resetPasswordRule)

        $desiredDacl = $targetAcl.GetSecurityDescriptorSddlForm(
            [System.Security.AccessControl.AccessControlSections]::Access
        )
        if ($currentDacl -eq $desiredDacl) {
            Write-Information "$TargetName already uses the AdminSDHolder DACL with Reset Password granted to $ComputerName" -InformationAction Continue
            return
        }

        $applyChange = $Force -and !$WhatIfPreference
        if (!$applyChange) {
            $applyChange = $PSCmdlet.ShouldProcess(
                $TargetName,
                "Replace the DACL with AdminSDHolder permissions, disable inheritance, and grant Reset Password to $ComputerName"
            )
        }
        if (!$applyChange) {
            return
        }

        $targetEntry.ObjectSecurity = $targetAcl
        $targetEntry.CommitChanges()
        Write-Information "Applied the AdminSDHolder DACL to $TargetName and granted Reset Password to $ComputerName" -InformationAction Continue
    }
    finally {
        $adminSDHolderEntry.Dispose()
        $targetEntry.Dispose()
    }
}

function Grant-ADPasswordExtendedRight {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TargetDistinguishedName,
        [Parameter(Mandatory = $true)]
        [string]$TargetServer,
        [Parameter(Mandatory = $true)]
        [System.Security.Principal.SecurityIdentifier]$PrincipalSid,
        [Parameter(Mandatory = $true)]
        [string]$PrincipalName,
        [Parameter(Mandatory = $true)]
        [string]$TargetName,
        [switch]$Force
    )

    $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry(
        "LDAP://$TargetServer/$TargetDistinguishedName"
    )

    try {
        $acl = $directoryEntry.ObjectSecurity
        $rules = $acl.GetAccessRules(
            $true,
            $true,
            [System.Security.Principal.SecurityIdentifier]
        )
        $missingRights = @()

        foreach ($extendedRight in @(
            [pscustomobject]@{
                Name = 'Change Password'
                Guid = $ChangePasswordExtendedRight
            }
            [pscustomobject]@{
                Name = 'Reset Password'
                Guid = $ResetPasswordExtendedRight
            }
        )) {
            $matchingRules = @($rules | Where-Object {
                $_.IdentityReference.Value -eq $PrincipalSid.Value -and
                (
                    (
                        $_.ActiveDirectoryRights -band
                        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                    ) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericAll -or
                    (
                        (
                            $_.ActiveDirectoryRights -band
                            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                        ) -eq [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight -and
                        ($_.ObjectType -eq [Guid]::Empty -or $_.ObjectType -eq $extendedRight.Guid)
                    )
                )
            })

            if ($matchingRules.AccessControlType -contains [System.Security.AccessControl.AccessControlType]::Deny) {
                throw [System.UnauthorizedAccessException] "A deny entry prevents $PrincipalName from receiving $($extendedRight.Name) on $TargetName"
            }
            if ($matchingRules.AccessControlType -notcontains [System.Security.AccessControl.AccessControlType]::Allow) {
                $missingRights += $extendedRight
            }
        }

        if ($missingRights.Count -eq 0) {
            Write-Information "$PrincipalName already has Change Password and Reset Password on $TargetName" -InformationAction Continue
            return
        }

        $rightNames = $missingRights.Name -join ', '
        $applyChange = $Force -and !$WhatIfPreference
        if (!$applyChange) {
            $applyChange = $PSCmdlet.ShouldProcess(
                $TargetName,
                "Grant $rightNames to $PrincipalName"
            )
        }
        if (!$applyChange) {
            return
        }

        foreach ($missingRight in $missingRights) {
            $accessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $PrincipalSid,
                [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                [System.Security.AccessControl.AccessControlType]::Allow,
                $missingRight.Guid
            )
            [void]$acl.AddAccessRule($accessRule)
        }

        $directoryEntry.ObjectSecurity = $acl
        $directoryEntry.CommitChanges()
        Write-Information "Granted $rightNames to $PrincipalName on $TargetName" -InformationAction Continue
    }
    finally {
        $directoryEntry.Dispose()
    }
}

$ScriptVersion = '0.1.20261009.1'
Write-Information "AzKerberosRollOver permission setup - Version $ScriptVersion" -InformationAction Continue

if (!(Get-Module -Name ActiveDirectory)) {
    Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false
    Write-Verbose 'Imported ActiveDirectory module'
}
else {
    Write-Verbose 'ActiveDirectory module is already imported'
}

$globalCatalogServer = '{0}:{1}' -f (
    Get-ADDomainController -Discover -Service GlobalCatalog -ErrorAction Stop
).HostName.Value, $GlobalCatalogPort

Write-Verbose "Using Global Catalog $globalCatalogServer"
$rolloverAccount = Resolve-ADUserAccount `
    -Identity $RollOverADAccountName `
    -GlobalCatalogServer $globalCatalogServer
$entraConnectComputer = Resolve-ADComputerAccount `
    -Identity $EntraConnectComputerName `
    -GlobalCatalogServer $globalCatalogServer
$azureADSSOAccount = Resolve-ADComputerAccount `
    -Identity $AzureADSSOAccountName `
    -GlobalCatalogServer $globalCatalogServer `
    -ForestWide

$rolloverPrincipalName = '{0}\{1}' -f (
    $rolloverAccount.Domain.NetBIOSName
), $rolloverAccount.Object.SamAccountName
$entraConnectPrincipalName = '{0}\{1}' -f (
    $entraConnectComputer.Domain.NetBIOSName
), $entraConnectComputer.Object.SamAccountName
$azureADSSOTargetName = '{0}\{1}' -f (
    $azureADSSOAccount.Domain.NetBIOSName
), $azureADSSOAccount.Object.SamAccountName

Write-Information "Rollover account: $rolloverPrincipalName" -InformationAction Continue
Write-Information "Entra Connect computer: $entraConnectPrincipalName" -InformationAction Continue
Write-Information "AzureADSSOAcc computer: $azureADSSOTargetName" -InformationAction Continue

$adminSDHolderDistinguishedName = "CN=AdminSDHolder,CN=System,$($rolloverAccount.Domain.DistinguishedName)"
Set-ADProtectedRolloverUserAcl `
    -TargetDistinguishedName $rolloverAccount.Object.DistinguishedName `
    -AdminSDHolderDistinguishedName $adminSDHolderDistinguishedName `
    -TargetServer $rolloverAccount.Domain.PDCEmulator `
    -ComputerSid $entraConnectComputer.Object.SID `
    -ComputerName $entraConnectPrincipalName `
    -TargetName $rolloverPrincipalName `
    -Force:$Force

Grant-ADPasswordExtendedRight `
    -TargetDistinguishedName $azureADSSOAccount.Object.DistinguishedName `
    -TargetServer $azureADSSOAccount.Domain.PDCEmulator `
    -PrincipalSid $rolloverAccount.Object.SID `
    -PrincipalName $rolloverPrincipalName `
    -TargetName $azureADSSOTargetName `
    -Force:$Force

Write-Information 'AzKerberosRollOver Active Directory permission setup completed.' -InformationAction Continue
