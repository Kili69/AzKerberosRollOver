#Requires -Version 5.1

<#
.SYNOPSIS
    Configures the Active Directory permissions required by AzKerberosRollOver.
.DESCRIPTION
    Replaces the rollover user DACL with the current AdminSDHolder DACL from its
    domain, disables permission inheritance, and grants the Entra Connect computer
    account Reset Password on the rollover user.

    The rollover user also receives Write and Reset Password rights on the
    AzureADSSOAcc computer account. When the scheduled task runs as
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

# Schema-independent GUID of the Active Directory "Reset Password" control access right.
$ResetPasswordExtendedRight = [Guid]'00299570-246d-11d0-a768-00aa006e0529'
$GlobalCatalogPort = 3268

<#
.SYNOPSIS
    Resolves the rollover user and its authoritative domain.
.DESCRIPTION
    Accepts a sAMAccountName, UPN, or DOMAIN\sAMAccountName. UPN searches use the
    Global Catalog so that accounts in any forest domain can be located. The matched
    object is then read again from its domain PDC emulator to return current identity
    and SID data together with the corresponding domain object.
.OUTPUTS
    PSCustomObject containing the resolved AD user in Object and its domain in Domain.
#>
function Resolve-ADUserAccount {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Identity,
        [Parameter(Mandatory = $true)]
        [string]$GlobalCatalogServer
    )

    # A plain sAMAccountName is resolved in the current domain by default.
    $searchServer = (Get-ADDomain -ErrorAction Stop).PDCEmulator
    $lookupValue = $Identity
    $lookupProperty = 'SamAccountName'

    # A domain-qualified name selects that domain's PDC; a UPN requires a forest-wide
    # Global Catalog search because its account domain is not known in advance.
    # Regex: ^ and $ anchor the complete value; (?<Domain>[^\\]+) captures one or
    # more non-backslash characters as Domain; \\ matches the literal separator;
    # (?<Name>[^\\]+) captures the remaining non-backslash characters as Name.
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

    # CanonicalName identifies the owning domain after a Global Catalog lookup.
    # Reading from its PDC avoids making ACL changes with stale replica information.
    # -split uses the literal slash as its regex delimiter and stops after two parts;
    # index 0 is therefore the DNS domain before the first slash.
    $domainDnsName = ($resolvedUsers[0].CanonicalName -split '/', 2)[0]
    $domain = Get-ADDomain -Identity $domainDnsName -ErrorAction Stop
    $user = Get-ADUser -Identity $resolvedUsers[0].DistinguishedName -Server $domain.PDCEmulator -Properties SID, SamAccountName, UserPrincipalName -ErrorAction Stop

    return [pscustomobject]@{
        Object = $user
        Domain = $domain
    }
}

<#
.SYNOPSIS
    Resolves an Active Directory computer and its authoritative domain.
.DESCRIPTION
    Accepts a computer name, DNS host name, sAMAccountName with an optional trailing
    dollar sign, or DOMAIN\computerName. ForestWide searches use the Global Catalog,
    which is required for locating AzureADSSOAcc when it is not in the current domain.
    The matched computer is read again from its domain PDC emulator.
.OUTPUTS
    PSCustomObject containing the resolved AD computer in Object and its domain in
    Domain.
#>
function Resolve-ADComputerAccount {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Identity,
        [Parameter(Mandatory = $true)]
        [string]$GlobalCatalogServer,
        [switch]$ForestWide
    )

    # Local computer identities are resolved against the current domain unless the
    # caller requests a forest-wide search.
    $searchServer = (Get-ADDomain -ErrorAction Stop).PDCEmulator
    $lookupValue = $Identity

    # Regex: ^ and $ anchor the complete value; (?<Domain>[^\\]+) captures one or
    # more non-backslash characters as Domain; \\ matches the literal separator;
    # (?<Name>[^\\]+) captures the remaining non-backslash characters as Name.
    if ($Identity -match '^(?<Domain>[^\\]+)\\(?<Name>[^\\]+)$') {
        $domain = Get-ADDomain -Identity $Matches.Domain -ErrorAction Stop
        $searchServer = $domain.PDCEmulator
        $lookupValue = $Matches.Name
    }
    elseif ($ForestWide) {
        $searchServer = $GlobalCatalogServer
    }

    # AD stores computer sAMAccountName values with a trailing dollar sign, while
    # callers commonly supply the computer name without it.
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

    # Resolve the owning domain and obtain the authoritative SID from its PDC.
    # -split uses the literal slash as its regex delimiter and stops after two parts;
    # index 0 is therefore the DNS domain before the first slash.
    $domainDnsName = ($resolvedComputers[0].CanonicalName -split '/', 2)[0]
    $domain = Get-ADDomain -Identity $domainDnsName -ErrorAction Stop
    $computer = Get-ADComputer -Identity $resolvedComputers[0].DistinguishedName -Server $domain.PDCEmulator -Properties SID, DNSHostName, SamAccountName -ErrorAction Stop

    return [pscustomobject]@{
        Object = $computer
        Domain = $domain
    }
}

<#
.SYNOPSIS
    Replaces the rollover user's DACL with a protected AdminSDHolder DACL copy.
.DESCRIPTION
    Copies only the current access-control section of AdminSDHolder to the rollover
    user, disables inheritance without preserving the user's previous ACEs, and adds
    Reset Password for the Entra Connect computer account.

    This is a point-in-time DACL copy. It does not add the user to a protected group
    and does not cause SDProp to maintain the rollover user's permissions.

    The operation is idempotent: no write occurs when the resulting DACL already
    matches the current target DACL.
#>
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

    # DirectoryEntry is used because it can replace the complete DACL and control
    # inheritance in one committed LDAP update.
    $targetEntry = New-Object System.DirectoryServices.DirectoryEntry(
        "LDAP://$TargetServer/$TargetDistinguishedName"
    )
    $adminSDHolderEntry = New-Object System.DirectoryServices.DirectoryEntry(
        "LDAP://$TargetServer/$AdminSDHolderDistinguishedName"
    )

    try {
        $targetAcl = $targetEntry.ObjectSecurity
        # Compare access-control SDDL only. Owner, group, and auditing information on
        # the rollover user are intentionally left unchanged.
        $currentDacl = $targetAcl.GetSecurityDescriptorSddlForm(
            [System.Security.AccessControl.AccessControlSections]::Access
        )
        $adminSDHolderDacl = $adminSDHolderEntry.ObjectSecurity.GetSecurityDescriptorSddlForm(
            [System.Security.AccessControl.AccessControlSections]::Access
        )

        # Start from the current AdminSDHolder DACL, then protect the copied DACL from
        # inheritance and discard all prior explicit or inherited target ACEs.
        $targetAcl.SetSecurityDescriptorSddlForm(
            $adminSDHolderDacl,
            [System.Security.AccessControl.AccessControlSections]::Access
        )
        $targetAcl.SetAccessRuleProtection($true, $false)

        # A task running as local SYSTEM accesses AD as the Entra Connect computer
        # account, so that computer SID receives the narrowly scoped reset right.
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

        # Force skips confirmation but never overrides the built-in WhatIf contract.
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

<#
.SYNOPSIS
    Delegates the rights needed to update AzureADSSOAcc.
.DESCRIPTION
    Ensures the rollover user has GenericWrite and the Reset Password extended right
    on the AzureADSSOAcc computer object. Existing GenericAll or unscoped matching
    allow ACEs satisfy the requirement. A matching deny ACE stops the operation
    because adding another allow ACE cannot override an explicit or inherited deny.

    Only missing allow ACEs are added, making repeated executions idempotent.
#>
function Grant-ADAzureADSSOPermission {
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
        # Resolve ACE identities to SIDs so comparisons remain independent of domain
        # name formatting and account-name translation.
        $rules = $acl.GetAccessRules(
            $true,
            $true,
            [System.Security.Principal.SecurityIdentifier]
        )
        $missingRights = @()

        # GenericWrite permits the object updates performed by Update-AzureADSSOForest;
        # Reset Password permits rotation of the computer account secret.
        foreach ($requiredRight in @(
            [pscustomobject]@{
                Name = 'Write'
                Right = [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
                ObjectType = [Guid]::Empty
            }
            [pscustomobject]@{
                Name = 'Reset Password'
                Right = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                ObjectType = $ResetPasswordExtendedRight
            }
        )) {
            # GenericAll always covers the requested right. Otherwise an unscoped ACE
            # or an ACE scoped to the exact control-access GUID must match.
            $matchingRules = @($rules | Where-Object {
                $_.IdentityReference.Value -eq $PrincipalSid.Value -and
                (
                    (
                        $_.ActiveDirectoryRights -band
                        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                    ) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericAll -or
                    (
                        (
                            $_.ActiveDirectoryRights -band $requiredRight.Right
                        ) -eq $requiredRight.Right -and
                        ($_.ObjectType -eq [Guid]::Empty -or $_.ObjectType -eq $requiredRight.ObjectType)
                    )
                )
            })

            # Deny takes precedence in effective AD access evaluation; silently adding
            # an allow ACE here would produce a success-shaped but unusable ACL.
            if ($matchingRules.AccessControlType -contains [System.Security.AccessControl.AccessControlType]::Deny) {
                throw [System.UnauthorizedAccessException] "A deny entry prevents $PrincipalName from receiving $($requiredRight.Name) on $TargetName"
            }
            if ($matchingRules.AccessControlType -notcontains [System.Security.AccessControl.AccessControlType]::Allow) {
                $missingRights += $requiredRight
            }
        }

        if ($missingRights.Count -eq 0) {
            Write-Information "$PrincipalName already has Write and Reset Password on $TargetName" -InformationAction Continue
            return
        }

        $rightNames = $missingRights.Name -join ', '
        # Force suppresses confirmation only; WhatIf remains authoritative.
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
                $missingRight.Right,
                [System.Security.AccessControl.AccessControlType]::Allow,
                $missingRight.ObjectType
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

$ScriptVersion = '0.1.20261009.4'
Write-Information "AzKerberosRollOver permission setup - Version $ScriptVersion" -InformationAction Continue

# Import explicitly with verbose disabled to avoid one import message per AD cmdlet.
if (!(Get-Module -Name ActiveDirectory)) {
    Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false
    Write-Verbose 'Imported ActiveDirectory module'
}
else {
    Write-Verbose 'ActiveDirectory module is already imported'
}

# Discover one Global Catalog for forest-wide UPN and AzureADSSOAcc resolution.
$globalCatalogServer = '{0}:{1}' -f (
    Get-ADDomainController -Discover -Service GlobalCatalog -ErrorAction Stop
).HostName.Value, $GlobalCatalogPort

Write-Verbose "Using Global Catalog $globalCatalogServer"

# Resolve all names before changing any ACL. This guarantees that a lookup error
# cannot leave only part of the requested permission configuration applied.
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

# Use unambiguous DOMAIN\sAMAccountName values in user-facing output and audit prompts.
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

# AdminSDHolder must come from the rollover user's own domain, not necessarily the
# current domain or the domain containing AzureADSSOAcc.
$adminSDHolderDistinguishedName = "CN=AdminSDHolder,CN=System,$($rolloverAccount.Domain.DistinguishedName)"

# Protect the worker account and authorize only this Entra Connect computer to reset
# the random password when the scheduled task executes as local SYSTEM.
Set-ADProtectedRolloverUserAcl `
    -TargetDistinguishedName $rolloverAccount.Object.DistinguishedName `
    -AdminSDHolderDistinguishedName $adminSDHolderDistinguishedName `
    -TargetServer $rolloverAccount.Domain.PDCEmulator `
    -ComputerSid $entraConnectComputer.Object.SID `
    -ComputerName $entraConnectPrincipalName `
    -TargetName $rolloverPrincipalName `
    -Force:$Force

# Delegate the minimum AzureADSSOAcc rights used by Update-AzureADSSOForest.
Grant-ADAzureADSSOPermission `
    -TargetDistinguishedName $azureADSSOAccount.Object.DistinguishedName `
    -TargetServer $azureADSSOAccount.Domain.PDCEmulator `
    -PrincipalSid $rolloverAccount.Object.SID `
    -PrincipalName $rolloverPrincipalName `
    -TargetName $azureADSSOTargetName `
    -Force:$Force

Write-Information 'AzKerberosRollOver Active Directory permission setup completed.' -InformationAction Continue
