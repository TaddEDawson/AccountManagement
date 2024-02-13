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
		Tests the user account for specific properties#>
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
				param ($SamAccountName)
				process
				{
					$FunctionName = "Test-User"
					Write-Verbose ("{0} Entering {1} {2}" -f [DateTime]::Now, $FunctionName, $SamAccountName)
		
					Write-Verbose ("{0} Leaving {1} {2}" -f [DateTime]::Now, $FunctionName, $SamAccountName)
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
				$processObject = [PSCustomObject]@{
					RunOn           = ($Env:COMPUTERNAME).ToUpper()
					RunAs           = ($Env:USERNAME).ToUpper()
					Begin           = ([DateTime]::Now)
					SamAccountName  = ($SamAccountName.ToUpper())
					TypeOfUser      = $null
					ActionToTake    = ($PSCmdlet.ParameterSetName.ToUpper())
					ADUser          = $null
					End             = $null
					Duration        = $null
					Message         = "No Action Taken"
					Exception       = $null
				} # $processObject
		
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
		
				$processObject.ADUser = $(
											try
											{
												Get-ADUser $processObject.SamAccountName -Properties *
											} # try
											catch
											{
												"NOT FOUND"
											}
										) # $processObject.ADUser       
		
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
						Test-User -SamAccountname $processObject.SamAccountName
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
		