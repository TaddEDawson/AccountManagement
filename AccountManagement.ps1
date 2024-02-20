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
    .EXAMPLE
        "TestUser", "TestUser-NSE", "TestUser-NSE", "TestUser-ADM" | .\AccountManagement.ps1 -TEST -Verbose
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
    ,
    # OU for user to be added to
    [Parameter(ParameterSetName = "TEST")]
    [Parameter(ParameterSetName = "NEW")]
    [Parameter(ParameterSetName = "UNLOCK")]
    [Parameter(ParameterSetName = "RESET")]
    [Parameter(ParameterSetName = "ENABLE")]
    [Parameter(ParameterSetName = "EXTEND")]
    [Parameter(ParameterSetName = "DISABLE")]
    [String]
    $EnabledUsersOU = "OU=Enabled Users,OU=User Accounts,DC=theuce,DC=onmicrosoft,DC=com"
    ,
    # OU for ADMIN Users to be added to
    [Parameter(ParameterSetName = "TEST")]
    [Parameter(ParameterSetName = "NEW")]
    [Parameter(ParameterSetName = "UNLOCK")]
    [Parameter(ParameterSetName = "RESET")]
    [Parameter(ParameterSetName = "ENABLE")]
    [Parameter(ParameterSetName = "EXTEND")]
    [Parameter(ParameterSetName = "DISABLE")]
    [String]
    $AdminOU = "OU=Accounts,OU=Admin,DC=theuce,DC=onmicrosoft,DC=com"
    ,
    # UPN suffix, defaults to "uce.cia.gov"
    [Parameter(ParameterSetName = "TEST")]
    [Parameter(ParameterSetName = "NEW")]
    [Parameter(ParameterSetName = "UNLOCK")]
    [Parameter(ParameterSetName = "RESET")]
    [Parameter(ParameterSetName = "ENABLE")]
    [Parameter(ParameterSetName = "EXTEND")]
    [Parameter(ParameterSetName = "DISABLE")]
    [String]
    $UPN = "uce.cia.gov"
    ,
    # Regular User Group Name for add, Add Users to the "UCE Users" Group to provide access to the WVD Users Host Pool
    [Parameter(ParameterSetName = "TEST")]
    [Parameter(ParameterSetName = "NEW")]
    [Parameter(ParameterSetName = "UNLOCK")]
    [Parameter(ParameterSetName = "RESET")]
    [Parameter(ParameterSetName = "ENABLE")]
    [Parameter(ParameterSetName = "EXTEND")]
    [Parameter(ParameterSetName = "DISABLE")]
    [String]
    $RegularUserGroup = "UCE Users"
    ,
    # UCE Admin Group Name
    [Parameter(ParameterSetName = "TEST")]
    [Parameter(ParameterSetName = "NEW")]
    [Parameter(ParameterSetName = "UNLOCK")]
    [Parameter(ParameterSetName = "RESET")]
    [Parameter(ParameterSetName = "ENABLE")]
    [Parameter(ParameterSetName = "EXTEND")]
    [Parameter(ParameterSetName = "DISABLE")]
    [String]
    $AdminUserGroup = "UCE Admins"
    ,
    # TAO User group
    [Parameter()]
    [Parameter(ParameterSetName = "TEST")]
    [Parameter(ParameterSetName = "NEW")]
    [Parameter(ParameterSetName = "UNLOCK")]
    [Parameter(ParameterSetName = "RESET")]
    [Parameter(ParameterSetName = "ENABLE")]
    [Parameter(ParameterSetName = "EXTEND")]
    [Parameter(ParameterSetName = "DISABLE")]
    [String] $TAOGroup = "TAO Users"
    ,
    #  AzureActiveDirectoryVM
    [Parameter(ParameterSetName = "TEST")]
    [Parameter(ParameterSetName = "NEW")]
    [Parameter(ParameterSetName = "UNLOCK")]
    [Parameter(ParameterSetName = "RESET")]
    [Parameter(ParameterSetName = "ENABLE")]
    [Parameter(ParameterSetName = "EXTEND")]
    [Parameter(ParameterSetName = "DISABLE")]
    [String] $AzureActiveDirectoryVM = "uce-adc-vm-2"
    ,
    # Onsite Only property
    [Parameter(ParameterSetName = "TEST")]
    [Parameter(ParameterSetName = "NEW")]
    [Parameter(ParameterSetName = "UNLOCK")]
    [Parameter(ParameterSetName = "RESET")]
    [Parameter(ParameterSetName = "ENABLE")]
    [Parameter(ParameterSetName = "EXTEND")]
    [Parameter(ParameterSetName = "DISABLE")]
    [String] $OnSiteOnlyProperty = 'msDS-cloudExtensionAttribute2'
) # param
begin
{
    Write-Verbose ("{0} Entering`tBeginProccessing {1}" -f [DateTime]::Now, $MyInvocation.MyCommand.Name)

    # Creat a Collection to hold the users processed
    $UsersProcessed         = [System.Collections.ArrayList]::new()
    $BeginProcessing        = [DateTime]::Now

    function Test-User
    {
        [CmdletBinding()]
        param
        (
            $processObject
        ) # param
        process
        {
            $FunctionName = "Test-User"
            Write-Verbose ("{0} `t`tEntering {1} {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)
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

            Write-Verbose ("{0} `t`tLeaving {1} {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)
        } # process
    } # function Test-User

    function New-User
    {
        [CmdletBinding()]
        param 
        (   
            $processObject
        ) # param
        process
        {
            $FunctionName = "New-User"
            Write-Verbose ("{0} `t`tEntering {1} {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)

            Write-Verbose ("{0} `t`tLeaving {1} {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)
        } # process
    } # function New-User

    function Unlock-User
    {
        [CmdletBinding()]
        param 
        (
            $processObject
        ) # param
        process
        {
            $FunctionName = "Unlock-User"
            Write-Verbose ("{0} `t`tEntering {1} {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)

            Write-Verbose ("{0} `t`tLeaving {1} {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)
        } # process
    } # function Unlock-User

    function Reset-User
    {
        [CmdletBinding()]
        param 
        (
            $processObject
        ) # param
        process
        {
            $FunctionName = "Reset-User"
            Write-Verbose ("{0} `t`tEntering {1} {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)

            Write-Verbose ("{0} `t`tLeaving {1} {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)
        } # process
    } # function Reset-User

    function Enable-User
    {
        [CmdletBinding()]
        param 
        (
            $processObject
        ) # param
        process
        {
            $FunctionName = "Enable-User"
            Write-Verbose ("{0} `t`tEntering {1} {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)

            Write-Verbose ("{0} `t`tLeaving {1} {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)
        } # process
    } # function Enable-User

function Update-User
    {
        [CmdletBinding()]
        param 
        (
            $processObject
        ) # param
        process
        {
            $FunctionName = "Update-User"
            Write-Verbose ("{0} `t`tEntering {1} {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)

            Write-Verbose ("{0} `t`tLeaving {1} {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)
        } # process
    } # function Extend-User

    function Disable-User
    {
        [CmdletBinding()]
        param 
        (
            $processObject
        ) # param
        process
        {
            $FunctionName = "Disable-User"
            Write-Verbose ("{0} `t`tEntering {1} {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)

            Write-Verbose ("{0} `t`tLeaving {1} {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)
        } # process
    } # function Disable-User

    function New-Password
    {
        <#
            .SYNOPSIS
                Generate a random string of a given length from a set of 4 groups of character sets
            .EXAMPLE
                New-Password
        #>
        [CmdletBinding()]
        param
        (
            # Length of random string, default to 14
            $Length = 14
        ) # param
        process
        {
            $FunctionName = "New-Password"
            Write-Verbose ("{0} `t`tEntering {1}" -f [DateTime]::Now, $FunctionName)
            function Get-NonRepeatingIndex
            {
                <#
                    .SYNOPSIS
                        Recursive function to get a random object that is not the same as the previous object.
                    .EXAMPLE
                        # For the collection 0..9, previous selected was 2, if get 2, try again
                        Get-NonRepeatingIndex -Collection @(0..9) -Previous 2 -Verbose
                #>
                [CmdletBinding()]
                param
                (
                    # Collection of objects to get a random object from
                    $Collection
                    ,
                    # The previous random object that was returned, requirement was to not have of same item
                    $Previous
                )
                process
                {
                    # Select a random item from the collection
                    $FirstRandom = $Collection | Get-Random
                    # Write-Verbose ("{0} {1} {2}" -f $FirstRandom, $Previous, ($FirstRandom -eq $Previous))
                    if ($FirstRandom -eq $Previous)
                    {
                        # Write-Verbose "Get a new value to check, continue until value is not equal to previous"
                        Do 
                        {
                            $ReturnValue = Get-NonRepeatingIndex -Collection $Collection -Previous $FirstRandom
    
                        #   Write-Verbose ("`t{0} {1} {2} {3}" -f $ReturnValue, $FirstRandom, ($ReturnValue -eq $FirstRandom), $Previous)
                        } Until ($ReturnValue -ne $Previous)
                        return $ReturnValue
                    }
                    else
                    {
                        return $FirstRandom
                    }
                } # process
            } # function Get-NonRepeatingIndex
            
            <# 
                Hashtable of the Character Sets to be used in the generation of password
                (letters i,l,o,q removed for disambiguation of initial email)
            #>
            $AllowedLetters = "abcdefghjkmnprstuvwxyz"
            $CharacterSets = @{
                # Special Characters
                1   = @("@","#","$","%")
                # Numbers (removed 0 and 1 for disambiguation of initial email)
                2   = @(2..9)
                # Lower case non-ambiguous letters
                3   = $AllowedLetters.ToCharArray()
                # Upper case non-ambiguous letters
                4   = $AllowedLetters.ToUpper().ToCharArray()
            } # $CharacterSets
    
            $RandomString = ""
            $PrevSet = $null
            Do
            {
                $CurrentSet =  $CharacterSets.Keys | Get-Random
                if($CurrentSet -eq $PrevSet)
                {
                    $CurrentSet = Get-NonRepeatingIndex -Collection $CharacterSets.Keys -Previous $PrevSet
                }
                $PrevSet = $CurrentSet
                $RandomString += ($CharacterSets[$CurrentSet] | Get-Random )
            }
            Until ($RandomString.Length -eq $Length)
            Write-Verbose ("{0} `t`tLeaving {1}" -f [DateTime]::Now, $FunctionName)
            return $RandomString
        } # process
    } # function New-Password

    Write-Verbose ("{0} Leaving `tBeginProccessing {1}" -f [DateTime]::Now, $MyInvocation.MyCommand.Name)
} # begin
process
{
    Write-Verbose ("{0} Entering`tProcessRecord {1}" -f [DateTime]::Now, $MyInvocation.MyCommand.Name)
    try
    {
        <#
        .SYNOPSIS
            This variable stores the action to be taken based on the parameter set name.

        .DESCRIPTION
            The $ActionToTake variable is used to determine the action to be taken in the script based on the parameter set name. It is assigned the value of the parameter set name converted to uppercase.
        #>
        $ActionToTake = ($PSCmdlet.ParameterSetName.ToUpper())

        <#
        .SYNOPSIS
        This script defines a process object used for account management.

        .DESCRIPTION
        The script creates a process object with various properties to track the execution of account management tasks. The process object includes information such as the computer name, username, start time, action to take, and result.

        .PARAMETER ActionToTake
        Specifies the action to be taken on the user account.
        #>

        $processObject = [PSCustomObject]@{
            RunOn                   = ($Env:COMPUTERNAME).ToUpper()
            RunAs                   = ($Env:USERNAME).ToUpper()
            Begin                   = ([DateTime]::Now)
            SamAccountName          = ($SamAccountName.ToUpper())
            TypeOfUser              = $null
            ActionToTake            = $ActionToTake
            ADUser                  = $null
            End                     = $null
            Duration                = $null
            Message                 = "No Action Taken"
            Results                 = $null
            NewPassword             = New-Password
            EnabledUsersOU          = $EnabledUsersOU
            AdminOU                 = $AdminOU
            UPN                     = $UPN
            RegularUserGroup        = $RegularUserGroup
            AdminUserGroup          = $AdminUserGroup
            $TAOGroup               = $TAOGroup
            AzureActiveDirectoryVM  = $AzureActiveDirectoryVM
            OnSiteOnlyProperty      = $OnSiteOnlyProperty
            OnSiteOnlyValue         = $null
            OnSiteOnly              = $true
            Exception               = $null
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
        ) # $processObject.ADUser

        <#
        .SYNOPSIS
            Executes different actions based on the value of $processObject.ActionTake.

        .DESCRIPTION
            This switch statement executes different actions based on the value of $processObject.ActionTake.
            The available actions are: DISABLE, EXTEND, ENABLE, NEW, RESET, UNLOCK. If none of these actions match,
            it will call the Test-User function with $processObject as a parameter.

        .PARAMETER processObject
            The object containing the action to be taken and the SamAccountName.
        #>

        switch ($processObject.ActionTake)
        {
            "DISABLE"   {
                $processObject.Results = Disable-User -processObject $processObject
            } # DISABLE
            "EXTEND"    {
                $processObject.Results = Update-User -processObject $processObject
            } # EXTEND
            "ENABLE"    {
                $processObject.Results = Enable-User -processObject $processObject
            } # ENABLE
            "NEW"       {
                $processObject.Results = New-User -processObject $processObject
            } # NEW
            "RESET"     {
                $processObject.Results = Reset-User -processObject $processObject
            } # RESET
            "UNLOCK"    {
                $processObject.Results = Unlock-User -processObject $processObject
            } # UNLOCK
            Default     {
                $processObject.Results = Test-User -processObject $processObject
            } # Default
        } # switch ($processObject.ActionTake)

        # Add the $processObject to the $UsersProcessed array list
        [void] $UsersProcessed.Add($processObject)
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
        Write-Verbose ("{0}`t`tProcessed ({1}) for ({2}) in ({3}) seconds" -f [DateTime]::Now, $processObject.SamAccountName, $processObject.ActionToTake, $processObject.Duration)
    } # finally

    Write-Verbose ("{0} Leaving `tProccessRecord {1}" -f [DateTime]::Now, $MyInvocation.MyCommand.Name)
} # process
end
{
    Write-Verbose ("{0} Entering EndProccessing {1}" -f [DateTime]::Now, $MyInvocation.MyCommand.Name)
        $EndProcessing          = [DateTime]::Now
        $DurationProcessing     = [Math]::Round(($EndProcessing - $BeginProcessing).TotalSeconds,2)
        Write-Verbose ("{0}`t Processed ({1}) Users in ({2}) seconds" -f [DateTime]::Now, $UsersProcessed.Count, $DurationProcessing)
    Write-Verbose ("{0} Leaving EndProccessing {1}" -f [DateTime]::Now, $MyInvocation.MyCommand.Name)
    # Retun the collection of Users Processed to the pipeline
    $UsersProcessed
} # end
