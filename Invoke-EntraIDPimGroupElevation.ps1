#https://learn.microsoft.com/en-us/graph/api/privilegedaccessgroupeligibilityschedulerequest-filterbycurrentuser?view=graph-rest-1.0&tabs=http


Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"

Invoke-MgFilterIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequestByCurrentUser -On "principal"

$MyContext = Get-MgContext
$Me = (Get-MgUser -UserId $MyContext.Account).Id

$MyEligibleGroups = Invoke-MgFilterIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequestByCurrentUser -On 'principal'

foreach ($group in $MyEligibleGroups) {
    $CurrentGroup = Get-MGGroup -GroupID $group.GroupId
    Write-Output "Eligible group: $($CurrentGroup.DisplayName) with ID $($CurrentGroup.Id)"
}

Import-Module Microsoft.Graph.Identity.Governance

$Now = Get-Date().ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$params = @{
	accessId = "member"
	principalId = $Me
	groupId = "d3152ac7-1c13-4e15-8cf4-7c806f3245d8"
	action = "selfActivate"
	scheduleInfo = @{
		startDateTime = Get-Date
		expiration = @{
			type = "afterDuration"
			duration = "PT2H"
		}
	}
	justification = "Activate assignment."
}

New-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -BodyParameter $params

