<#PSScriptInfo
.VERSION 1.3
.GUID 78e7abb6-aeae-4486-81e8-9b61e8b2e3e3
.AUTHOR JanKetilSkanke
.COMPANYNAME CloudWay
.COPYRIGHT 
.TAGS EntraID, PIM, Privileged Identity Management
.LICENSEURI https://github.com/MSEndpointMgr/EntraIDPIMElevations/blob/main/LICENSE
.PROJECTURI https://github.com/MSEndpointMgr/EntraIDPIMElevations
.ICONURI 
.EXTERNALMODULEDEPENDENCIES Microsoft.Graph.Users, Microsoft.Graph.Identity.Governance
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
.PRIVATEDATA
#>

<#
.SYNOPSIS
    Name: invoke-EntraIDPimElevations.ps1
    Script to activate Eligible roles in Entra ID PIM for a user
.DESCRIPTION
    Script to activate Eligible roles in Entra ID PIM for a user
.PARAMETER RolesToActivate
    Comma separated list of roles to activate, Example -RolesToActivate "Global Reader, Intune Administrator"
.PARAMETER Justification
    Justification for activating the roles
.PARAMETER ActivationDuration 
    Duration in hours for the activation, default is 8 hours
.PARAMETER GetAvailableRoles
    Switch to get all available eligible roles for the user
.PARAMETER Consent
    Switch to request consent on all required scopes
.PARAMETER ForceRefresh
    Switch to force refresh of your logon context (tokens)
.EXAMPLE 
  invoke-EntraIDPimElevations.ps1 -RolesToActivate "Global Reader, Intune Administrator" -Justification "Testing" -ActivationDuration 4
  invoke-EntraIDPimElevations.ps1 -GetAvailableRoles -ForceRefresh
  invoke-EntraIDPimElevations.ps1 -Consent

.NOTES
    Version:        1.3
    Author:         Jan Ketil Skanke (@JankeSkanke)
    Creation Date:  2023-12-13
    Author:     Jan Ketil Skanke
    Contact:     @JankeSkanke
    Created:     2023-12-13
    Version history:
    1.1.0 - (2023-12-13) Script Created
    1.2.0 - (2023-12-15) Added consent switch and cleaned up code
    1.3.0 . (2024-01-10) Added ForceRefresh switch and added context to Windows Title
#>
#Requires -Modules Microsoft.Graph.Identity.Governance, Microsoft.Graph.Users
param (
    [Parameter(Mandatory=$true, ParameterSetName='ActivateRoles', HelpMessage="Specifies the roles to activate.")]
    [ValidateNotNullOrEmpty()]
    [string]$RolesToActivate,
    [Parameter(Mandatory=$true, ParameterSetName='ActivateRoles', HelpMessage="Specifies justification for activation.")]
    [ValidateNotNullOrEmpty()]
    [ValidateLength(6, 200)]
    [string]$Justification,
    [Parameter(Mandatory=$false, ParameterSetName='ActivateRoles', HelpMessage="Specifies the duration of the activation.")]
    [int]$ActivationDuration = 8,
    [Parameter(Mandatory=$false, ParameterSetName='GetRoles', HelpMessage="Get all available eligible roles for the user.")]
    [switch]$GetAvailableRoles,
    [Parameter(Mandatory=$false, ParameterSetName='GetRoles', HelpMessage="Get all available eligible roles for the user.")]
    [Parameter(Mandatory=$false, ParameterSetName='ActivateRoles', HelpMessage="Get all available eligible roles for the user.")]
    [switch]$ForceRefresh,
    [Parameter(Mandatory=$true, ParameterSetName='Consent', HelpMessage="Request consent on scopes.")]
    [switch]$Consent
)
# Clear out any existing tokens 
if ($ForceRefresh) {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}

# Check if consent is requested and request it if true
if ($Consent) {
    try {
        Connect-MgGraph -Scopes "RoleEligibilitySchedule.Read.Directory, RoleAssignmentSchedule.ReadWrite.Directory, User.Read.All" -NoWelcome -ErrorAction Stop
        Write-Host "Consent OK, exiting script" -ForegroundColor Green
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    exit      
    }
    catch {
        Write-Host "Consent not granted, admin request might be needed" -ForegroundColor Yellow
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        exit
    }
}

# Connect to Graph 
try {
    Connect-MgGraph -NoWelcome -ErrorAction Stop 
    # Get auth context
    $MyContext = Get-MgContext
    $Me = (Get-MgUser -UserId $MyContext.Account).Id
    if ($MyContext.Scopes -notcontains "RoleEligibilitySchedule.Read.Directory" -or $MyContext.Scopes -notcontains "RoleAssignmentSchedule.ReadWrite.Directory" -or $MyContext.Scopes -notcontains "User.Read.All" ) {
        Write-Warning "Missing consent, run script with -Consent switch to request consent"
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        exit
    }
    $host.ui.RawUI.WindowTitle = $($MyContext.Account)
    Write-Output "Connected as $($MyContext.Account)"     
}
catch {
    Write-Warning "Failed to connect to Graph: $($_.Exception.Message), exiting script"
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    exit
}
# Try to get all eligible roles for user for processing
try {
    $myRoles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -ExpandProperty RoleDefinition -All -Filter "principalId eq '$Me'" -ErrorAction Stop
}
catch {
    Write-Warning "Failed to get eligible roles: $($_.Exception.Message), exiting script"
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    exit
}

switch ($PSCmdlet.ParameterSetName) {
    "GetRoles"{
        if ($($myroles.count) -eq 0) {
            Write-Warning "No eligible roles found, exiting script"
            break
        }
        Write-Output "You have $($myroles.count) eligible roles and they are:"
        Write-Output $($myRoles.RoleDefinition.DisplayName | Sort-Object | Format-Table)
        break
    }
    "ActivateRoles"{
        if ($($myroles.count) -eq 0) {
            Write-Warning "No eligible roles found, exiting script"
            break
        }
        $MyRolesNames = $myRoles.RoleDefinition.DisplayName
        $Roles = $RolesToActivate.Split(",") | ForEach-Object { $_.Trim() }
        foreach ($role in $Roles) {
            if ($role -notin $MyRolesNames) {
                Write-Warning "Role $role is not eligible for you to activate, exiting script"
                exit
            }
        }
        Write-Host "You are about to activate the following roles:" -ForegroundColor Green
        Write-Output $Roles | Sort-Object | Format-Table
        Write-Output "This will be active for $($ActivationDuration) hours"
        Write-Host "Are you sure you want to continue? (Y/N)" -ForegroundColor Yellow
        $answer = Read-Host
        if ($answer -ne "Y") {
            Write-Output "Exiting script"
            break
        }
        Write-Output "Activating roles: $RolesToActivate"
        Write-Output "Reason: $Justification"
        
        # Activate the roles
        foreach ($role in $Roles) {
            $myRole = $myroles | Where-Object {$_.RoleDefinition.DisplayName -eq $role}
            #Write-Output $myRole
            $params = @{
                Action = "selfActivate"
                PrincipalId = $myRole.PrincipalId
                RoleDefinitionId = $myRole.RoleDefinitionId
                DirectoryScopeId = $myRole.DirectoryScopeId
                Justification = "Enable $role role with reason $Justification"
                ScheduleInfo = @{
                    StartDateTime = Get-Date
                    Expiration = @{
                        Type = "AfterDuration"
                        Duration = "PT$($ActivationDuration)H"
                    }
                }
            }
            try {
                $Activation = New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params -ErrorAction Stop
                Write-Output "Activated role $($role) for $($ActivationDuration) hours from UTC $($Activation.ScheduleInfo.StartDateTime) and will expire at UTC $($Activation.ScheduleInfo.StartDateTime.AddHours($ActivationDuration))" 
            }
            catch {
                <#Do this if a terminating exception happens#>
                Write-Warning "Error activating role $($role): $($_.Exception.Message)"
                
            }
        }
    }
    Default {exit}
}
#Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
