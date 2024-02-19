#requires -module Az.Resources
$scope = "/" # "/" stands for tenant level resource
$MyResources = Get-AzRoleEligibilitySchedule -Scope $scope -Filter "asTarget()"

$MyResources.ScopeType
$MyResources.Scope
$MyResources.RoleDefinitionDisplayName
$MyResources.ScopeDisplayName

foreach ($resource in $MyResources)
{
    Write-Output "ScopeType: $($resource.ScopeType)"
    Write-output "Scope: $($resource.Scope)"
    Write-Output "RoleDefinitionDisplayName: $($resource.RoleDefinitionDisplayName)"
    Write-Output "ScopeDisplayName: $($resource.ScopeDisplayName)"
    Write-Output " "
}

$Role = $MyResources[2]
$expirationDuration = "PT1H"
$Justification = "Justification for the request"

$startTime = Get-Date -Format o 

$roleActivateParams = @{
    Name                            = New-Guid
    Scope                           = $Role.ScopeId
    PrincipalId                     = $Role.PrincipalId
    RoleDefinitionId                = $Role.RoleDefinitionId
    RequestType                     = 'SelfActivate'
    LinkedRoleEligibilityScheduleId = $Role.Name
    ExpirationDuration              = $expirationDuration
    Justification                   = $Justification
}

$Request = New-AzRoleAssignmentScheduleRequest @roleActivateParams -ErrorAction Stop



Foreach ($Module in $Modules)
{
    $ModuleName = $Module.Name
    Write-Host "Uninstall-Module $ModuleName $($Version)"
    Uninstall-Module $ModuleName -RequiredVersion $Version -Force
    
}