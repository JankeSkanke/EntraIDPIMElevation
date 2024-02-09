#https://learn.microsoft.com/en-us/graph/api/privilegedaccessgroupeligibilityschedulerequest-filterbycurrentuser?view=graph-rest-1.0&tabs=http

Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"

$MyContext = Get-MgContext
$Me = (Get-MgUser -UserId $MyContext.Account).Id

$MyEligibleGroups = Get-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleInstance -Filter "principalId eq '$Me'" | Select-Object accessId, GroupId

foreach ($group in $MyEligibleGroups) {
    $CurrentGroup = Get-MGGroup -GroupID $group.GroupId
    Write-Output "Type: $($group.accessId) : $($CurrentGroup.DisplayName)"
}
$GroupNameToElevate = "EntraID PIM Group 2"
$MyGroupIdToElevate = (Get-MGGroup -Filter "displayName eq '$($GroupNameToElevate)'").Id
$Reason = "Active group membership"
$ActivationDuration = 1
$accessId = ($MyEligibleGroups | Where-Object {$_.GroupId -eq $MyGroupIdToElevate}).accessId 

$params = @{
	accessId = $accessId
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
try {
	$MyActivation = New-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -BodyParameter $params -ErrorAction Stop 	
	Write-Output "Actived group $($GroupNameToElevate) $($accessId) for $($ActivationDuration) hours"
}
catch {
	<#Do this if a terminating exception happens#>
	Write-Output "Failed activating $($accessId) to group $($GroupNameToElevate)"
	Write-Warning "$($_.Exception.Message)"
}


