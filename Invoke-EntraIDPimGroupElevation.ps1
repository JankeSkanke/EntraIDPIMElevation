#https://learn.microsoft.com/en-us/graph/api/privilegedaccessgroupeligibilityschedulerequest-filterbycurrentuser?view=graph-rest-1.0&tabs=http

Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"

Invoke-MgFilterIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequestByCurrentUser 

Invoke-MgFilterIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequestByCurrentUser -On "principal" 

-ExpandProperty RoleDefinition -All 

$MyContext = Get-MgContext
$Me = (Get-MgUser -UserId $MyContext.Account).Id

$MyEligibleGroups = Get-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleInstance -Filter "principalId eq '$Me'" | Select-Object accessId, GroupId

foreach ($group in $MyEligibleGroups) {
    $CurrentGroup = Get-MGGroup -GroupID $group.GroupId
    Write-Output "Eligible group: $($CurrentGroup.DisplayName) with ID $($CurrentGroup.Id)"
}

$MyGroupIdToElevate = (Get-MGGroup -Filter "displayName eq 'EntraID PIM Group 3'").Id
$Reason = "Active group membership"
$ActivationDuration = 1

$params = @{
	accessId = "member"
	principalId = $Me
	groupId = $MyGroupIdToElevate
	action = "selfActivate"
	scheduleInfo = @{
		startDateTime = Get-Date
		expiration = @{
			type = "afterDuration"
			duration = "PT$($ActivationDuration)H"
		}
	}
	justification = $Reason
}
$MyActivation = New-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -BodyParameter $params   
$MyActivation | fl *


Invoke-MgFilterIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequestByCurrentUser -On "principal" | Select-Object -ExpandProperty Group


