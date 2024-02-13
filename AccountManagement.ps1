<#
	.SYNOPSIS
		This script is used to manage user accounts in Active Directory.
	.DESCRIPTION
		This script is used to manage user accounts in Active Directory.
	.PARAMETER SamAccountName
		The SamAccountName of the user account to manage
	.PARAMETER TEST
		Used to test the user account for specific properties
	.PARAMETER NEW
		Used to create a new user account
	.PARAMETER UNLOCK
		Used to unlock a user account
	.PARAMETER RESET
		Used to reset a user account
	.PARAMETER ENABLE
		Used to enable a user account
	.PARAMETER EXTEND
		Used to extend a user account
	.PARAMETER DISABLE
		Used to disable a user account
	.EXAMPLE
		.\AccountManagement.ps1 -SamAccountName "jsmith" -TEST -Verbose
		Tests the user account for specific properties
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = "TEST")]
param
(
	[Parameter(ParameterSetName = "TEST", ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory = $true)]
	[Parameter(ParameterSetName = "NEW", ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory = $true)]
	[Parameter(ParameterSetName = "UNLOCK", ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory = $true)]
	[Parameter(ParameterSetName = "RESET", ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory = $true)]
	[Parameter(ParameterSetName = "ENABLE", ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory = $true)]
	[Parameter(ParameterSetName = "EXTEND", ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory = $true)]
	[Parameter(ParameterSetName = "DISABLE", ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory = $true)]
	[string]$SamAccountName
	,

	[Parameter(ParameterSetName = "TEST")]
	[switch]$TEST
	,

	[Parameter(ParameterSetName = "NEW")]
	[switch]$NEW
	,

	[Parameter(ParameterSetName = "UNLOCK")]
	[switch]$UNLOCK
	,

	[Parameter(ParameterSetName = "RESET")]
	[switch]$RESET
	,

	[Parameter(ParameterSetName = "ENABLE")]
	[switch]$ENABLE
	,

	[Parameter(ParameterSetName = "EXTEND")]
	[switch]$EXTEND
	,

	[Parameter(ParameterSetName = "DISABLE")]
	[switch]$DISABLE
) # End of param
process 
{

	class AccountManagement
	{
		[string]$SamAccountName
	
		AccountManagement([string]$SamAccountName) 
		{
			$this.SamAccountName = $SamAccountName
		} # End of constructor
	
		[void] UnlockUser() 
		{
			# Implementation for unlocking user
		} # End of method UnlockUser
	
		[void] ResetUser() 
		{
			# Implementation for resetting user
		}
	
		[void] NewUser() 
		{
			# Implementation for creating new user
		} # End of method NewUser
	
		[void] EnableUser() 
		{
			# Implementation for enabling user
		} # End of method EnableUser
	
		[void] ExtendUser() 
		{
			# Implementation for extending user
		} # End of method ExtendUser
	
		[void] DisableUser() 
		{
			# Implementation for disabling user
		} # End of method DisableUser
	
		[void] Execute()
		{
			switch ($PSCmdlet.ParameterSetName) {
				"UNLOCK" { $this.UnlockUser() }
				"RESET" { $this.ResetUser() }
				"NEW" { $this.NewUser() }
				"ENABLE" { $this.EnableUser() }
				"EXTEND" { $this.ExtendUser() }
				"DISABLE" { $this.DisableUser() }
				default { Write-Verbose $("Executing TEST parameter set for SamAccountName: {0} -f $this.SamAccountName") }
			} # End of switch
		} # End of method Execute
	} # End of class AccountManagement
	
	# Main script logic
	$accountManagement = [AccountManagement]::new($SamAccountName)
	$accountManagement.Execute()
} # End of process

