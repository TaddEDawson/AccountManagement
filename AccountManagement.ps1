#Requires -Module ActiveDirectory
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
[CmdletBinding(
	DefaultParameterSetName = "TEST",
	SupportsShouldProcess
)]
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
) # param
begin
{
	Write-Verbose ("{0} Entering BeginProccessing" -f [DateTime]::Now)

	# Creat a Collection to hold the users processed
	$UsersProcessed         = [System.Collections.ArrayList]::new()
	$BeginProcessing        = [DateTime]::Now

	function Test-User
	{
		[CmdletBinding()]
		param
        (
            $processObject
        )
		process
		{
			$FunctionName = "Test-User"
			Write-Verbose ("{0} Entering {1} {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)
            if($null -ne $processObject.ADUser)
            {
                $UserExists = $true
            } # User exists in AD
            else
            {
                $UserExists = $false
            } # User not found in AD

            [PSCustomObject]@{
                Action = $FunctionName
                UserExists = $UserExists
            } # [PSCustomObject]

			Write-Verbose ("{0} Leaving {1} {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)
		} # process
	} # function Test-User

	function New-User
	{
		[CmdletBinding()]
		param ($SamAccountName)
		process
		{
			$FunctionName = "New-User"
			Write-Verbose ("{0} Entering {1} {2}" -f [DateTime]::Now, $FunctionName, $SamAccountName)

			Write-Verbose ("{0} Leaving {1} {2}" -f [DateTime]::Now, $FunctionName, $SamAccountName)
		} # process
	} # function New-User

	function Unlock-User
	{
		[CmdletBinding()]
		param ($SamAccountName)
		process
		{
			$FunctionName = "Unlock-User"
			Write-Verbose ("{0} Entering {1} {2}" -f [DateTime]::Now, $FunctionName, $SamAccountName)

			Write-Verbose ("{0} Leaving {1} {2}" -f [DateTime]::Now, $FunctionName, $SamAccountName)
		} # process
	} # function Unlock-User

	function Reset-User
	{
		[CmdletBinding()]
		param ($SamAccountName)
		process
		{
			$FunctionName = "Reset-User"
			Write-Verbose ("{0} Entering {1} {2}" -f [DateTime]::Now, $FunctionName, $SamAccountName)

			Write-Verbose ("{0} Leaving {1} {2}" -f [DateTime]::Now, $FunctionName, $SamAccountName)
		} # process
	} # function Reset-User

	function Enable-User
	{
		[CmdletBinding()]
		param ($SamAccountName)
		process
		{
			$FunctionName = "Enable-User"
			Write-Verbose ("{0} Entering {1} {2}" -f [DateTime]::Now, $FunctionName, $SamAccountName)

			Write-Verbose ("{0} Leaving {1} {2}" -f [DateTime]::Now, $FunctionName, $SamAccountName)
		} # process
	} # function Enable-User

function Update-User
	{
		[CmdletBinding()]
		param ($SamAccountName)
		process
		{
			$FunctionName = "Update-User"
			Write-Verbose ("{0} Entering {1} {2}" -f [DateTime]::Now, $FunctionName, $SamAccountName)

			Write-Verbose ("{0} Leaving {1} {2}" -f [DateTime]::Now, $FunctionName, $SamAccountName)
		} # process
	} # function Extend-User

	function Disable-User
	{
		[CmdletBinding()]
		param ($SamAccountName)
		process
		{
			$FunctionName = "Disable-User"
			Write-Verbose ("{0} Entering {1} {2}" -f [DateTime]::Now, $FunctionName, $SamAccountName)

			Write-Verbose ("{0} Leaving {1} {2}" -f [DateTime]::Now, $FunctionName, $SamAccountName)
		} # process
	} # function Disable-User

	function New-Password
	{
		[CmdletBinding()]
		param()
		process
		{
			$FunctionName = "New-Password"
			Write-Verbose ("{0} Entering {1}" -f [DateTime]::Now, $FunctionName)

			Write-Verbose ("{0} Leaving {1}" -f [DateTime]::Now, $FunctionName)
		} # process
	}

	Write-Verbose ("{0} Leaving BeginProccessing" -f [DateTime]::Now)
} # begin
process
{
	Write-Verbose ("{0} Entering ProcessRecord" -f [DateTime]::Now)
	try
	{
<#
.SYNOPSIS
	This variable stores the action to be taken based on the parameter set name.

.DESCRIPTION
	The $ActionToTake variable is used to determine the action to be taken in the script based on the parameter set name. It is assigned the value of the parameter set name converted to uppercase.

.PARAMETER ParameterSetName
	Specifies the name of the parameter set.

.EXAMPLE
	$ActionToTake = ($PSCmdlet.ParameterSetName.ToUpper())
#>

<#
.SYNOPSIS
This script defines a process object used for account management.

.DESCRIPTION
The script creates a process object with various properties to track the execution of account management tasks. The process object includes information such as the computer name, username, start time, action to take, and result.

.PARAMETER ActionToTake
Specifies the action to be taken on the user account.

.INPUTS
None.

.OUTPUTS
None.

.NOTES
Author: [Your Name]
Date: [Current Date]

.EXAMPLE
$processObject = [PSCustomObject]@{
	RunOn           = ($Env:COMPUTERNAME).ToUpper()
	RunAs           = ($Env:USERNAME).ToUpper()
	Begin           = ([DateTime]::Now)
	SamAccountName  = ($SamAccountName.ToUpper())
	TypeOfUser      = $null
	ActionToTake    = $ActionToTake
	ADUser          = $null
	End             = $null
	Duration        = $null
	Message         = "No Action Taken"
	Results         = $null
	Exception       = $null
}
#>
$ActionToTake = ($PSCmdlet.ParameterSetName.ToUpper())

$processObject = [PSCustomObject]@{
	RunOn           = ($Env:COMPUTERNAME).ToUpper()
	RunAs           = ($Env:USERNAME).ToUpper()
	Begin           = ([DateTime]::Now)
	SamAccountName  = ($SamAccountName.ToUpper())
	TypeOfUser      = $null
	ActionToTake    = $ActionToTake
	ADUser          = $null
	End             = $null
	Duration        = $null
	Message         = "No Action Taken"
	Results         = $null
	Exception       = $null
} # $processObject

		<#
		.SYNOPSIS
		Determines the type of user based on the SamAccountName.

		.DESCRIPTION
		This code block assigns a value to the $processObject.TypeOfUser variable based on the SamAccountName suffix. If the SamAccountName ends with "-ADM", the type of user is set to "ADM". If it ends with "-TST", the type of user is set to "TEST". If it ends with "-NSE", the type of user is set to "NSE". For any other suffix, the type of user is set to "STANDARD".

		.PARAMETER processObject
		The object representing the user being processed.

		.OUTPUTS
		The type of user assigned to the $processObject.TypeOfUser variable.

		.EXAMPLE
		$processObject = Get-User -Identity "JohnDoe"
		$processObject.SamAccountName = "JohnDoe-TST"
		$processObject.TypeOfUser = DetermineUserType -processObject $processObject
		# The $processObject.TypeOfUser variable will be set to "TEST".

		.NOTES
		This code block assumes that the $processObject variable has a property named "SamAccountName" which represents the user's account name.

		#>

		$processObject.TypeOfUser = $(
			if($processObject.SamAccountName.EndsWith("-ADM"))
			{
				"ADM"
			} # ADM
			elseif($processObject.SamAccountName.EndsWith("-TST"))
			{
				"TEST"
			} # TST
			elseif($processObject.SamAccountName.EndsWith("-NSE"))
			{
				"NSE"
			} # NSE
			else
			{
				"STANDARD"
			} # Default type of user to STANDARD
		) #  $processObject.TypeOfUser

		<#
		.SYNOPSIS
		Retrieves an Active Directory user object based on the provided SamAccountName.

		.DESCRIPTION
		This code block attempts to retrieve an Active Directory user object using the Get-ADUser cmdlet.
		If the user is found, the user object is assigned to the $processObject.ADUser variable.
		If the user is not found, the string "NOT FOUND" is assigned to the $processObject.ADUser variable.

		.PARAMETER SamAccountName
		The SamAccountName of the user to retrieve.

		.OUTPUTS
		System.Management.Automation.PSCustomObject

		.NOTES
		This code block requires the Active Directory module to be installed.

		.EXAMPLE
		$processObject.SamAccountName = "john.doe"
		$processObject.ADUser = Get-ADUserObject -SamAccountName $processObject.SamAccountName
		#>

		$processObject.ADUser = $(
			try
			{
				Get-ADUser $processObject.SamAccountName -Properties *
			}
			catch
			{
				"NOT FOUND"
			}
		)

		<#
		.SYNOPSIS
			Executes different actions based on the value of $processObject.ActionTake.

		.DESCRIPTION
			This switch statement executes different actions based on the value of $processObject.ActionTake.
			The available actions are: DISABLE, EXTEND, ENABLE, NEW, RESET, UNLOCK. If none of these actions match,
			it will call the Test-User function with $processObject as a parameter.

		.PARAMETER processObject
			The object containing the action to be taken and the SamAccountName.

		.EXAMPLE
			$processObject = @{
				ActionTake = "DISABLE"
				SamAccountName = "JohnDoe"
			}
			Switch-Action -processObject $processObject

			This example will call the Disable-User function with the SamAccountName "JohnDoe".

		#>

		switch ($processObject.ActionTake)
		{
			"DISABLE"   {
				Disable-User -SamAccountname $processObject.SamAccountName
			} # DISABLE
			"EXTEND"    {
				Update-User -SamAccountname $processObject.SamAccountName
			} # EXTEND
			"ENABLE"    {
				Enable-User -SamAccountname $processObject.SamAccountName
			} # ENABLE
			"NEW"       {
				New-User -SamAccountname $processObject.SamAccountName
			} # NEW
			"RESET"     {
				Reset-User -SamAccountname $processObject.SamAccountName
			} # RESET
			"UNLOCK"    {
				Unlock-User -SamAccountname $processObject.SamAccountName
			} # UNLOCK
			Default     {
				$processObject.Results = Test-User -processObject $processObject
			} # Default
		} # switch ($processObject.ActionTake)

	} # try
	catch
	{
		$processObject.Exception = $Error[0].Exception
		Write-Error ("{0} EXCEPTION : ({1})" -f [DateTime]::Now, $processObject.Exception)
	} # catch
	finally
	{
		$processObject.End      = [DateTime]::Now
		$processObject.Duration = [Math]::Round(($processObject.End - $processObject.Begin).TotalSeconds,2)
		Write-Verbose ("{0} `t Processed ({1}) for ({2} in ({3}) seconds" -f [DateTime]::Now, $processObject.SamAccountName, $processObject.ActionToTake, $processObject.Duration)
	} # finally


	Write-Verbose ("{0} Leaving ProccessRecord" -f [DateTime]::Now)
} # process
end
{
	Write-Verbose ("{0} Entering EndProccessing" -f [DateTime]::Now)
		$EndProcessing          = [DateTime]::Now
		$DurationProcessing     = [Math]::Round(($EndProcessing - $BeginProcessing).TotalSeconds,2)
		Write-Verbose ("{0} `t Processed ({1}) Users in ({2}) seconds" -f [DateTime]::Now, $UsersProcessed.Count, $DurationProcessing)
	Write-Verbose ("{0} Leaving EndProccessing" -f [DateTime]::Now)
} # end
