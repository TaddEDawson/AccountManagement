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
    .PARAMETER EnabledUsersOU
        The OU for user to be added to
    .PARAMETER AdminOU
        The OU for ADMIN Users to be added to
    .PARAMETER TestOU
        The OU for TEST Users to be added to
    .PARAMETER NSEOU
        The OU for NSE Users to be added to
    .PARAMETER DisabledUsersOU
        The OU for Disabled Users to be added to
    .PARAMETER UPN
        UPN suffix, defaults to "uce.cia.gov"
    .PARAMETER RegularUserGroup
        Regular User Group Name for add, Add Users to the "UCE Users" Group to provide access to the WVD Users Host Pool
    .PARAMETER AdminUserGroup
        UCE Admin Group Name
    .PARAMETER TAOGroup
        TAO User group
    .PARAMETER AzureActiveDirectoryVM
        AzureActiveDirectoryVM
    .PARAMETER OnSiteOnlyProperty
        Onsite Only property
    .PARAMETER OnSiteOnlyValue
        Onsite Only value
    .PARAMETER OnSiteOnly
        Onsite Only

    .EXAMPLE
        .\AccountManagement.ps1 -SamAccountName "jsmith" -TEST -Verbose -WhatIf
        Tests the user account for specific properties
    .EXAMPLE
        "TestUser", "TestUser-NSE", "TestUser-NSE", "TestUser-ADM" | .\AccountManagement.ps1 -TEST -Verbose -WhatIf

    .NOTES
        AccountExpirationDate   = (Get-Date).AddYears(1)
#>
[CmdletBinding(
    DefaultParameterSetName = "TEST",
    SupportsShouldProcess
)]
param
(
    # SamAccount Name to process, without the domain
    [Parameter(ParameterSetName = "TEST", ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory = $true)]
    [Parameter(ParameterSetName = "NEW", ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory = $true)]
    [Parameter(ParameterSetName = "UNLOCK", ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory = $true)]
    [Parameter(ParameterSetName = "RESET", ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory = $true)]
    [Parameter(ParameterSetName = "ENABLE", ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory = $true)]
    [Parameter(ParameterSetName = "EXTEND", ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory = $true)]
    [Parameter(ParameterSetName = "DISABLE", ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory = $true)]
    [String] $SamAccountName
    ,
    # Switch to select TEST account(s) only
    [Parameter(ParameterSetName = "TEST")]
    [switch] $TEST
    ,
    # Switch to select NEW account(s) only
    [Parameter(ParameterSetName = "NEW")]
    [switch] $NEW
    ,
    # Switch to select UNLOCK account(s) only
    [Parameter(ParameterSetName = "UNLOCK")]
    [switch] $UNLOCK
    ,
    # Switch to select RESET account(s) only
    [Parameter(ParameterSetName = "RESET")]
    [switch] $RESET
    ,
    # Switch to select ENABLE account(s) only
    [Parameter(ParameterSetName = "ENABLE")]
    [switch] $ENABLE
    ,
    # Switch to select EXTEND account(s) only
    [Parameter(ParameterSetName = "EXTEND")]
    [switch] $EXTEND
    ,
    # Switch to select DISABLE account(s) only
    [Parameter(ParameterSetName = "DISABLE")]
    [switch] $DISABLE
    ,
    # OU for user to be added to
    [Parameter(ParameterSetName = "TEST")]
    [Parameter(ParameterSetName = "NEW")]
    [Parameter(ParameterSetName = "UNLOCK")]
    [Parameter(ParameterSetName = "RESET")]
    [Parameter(ParameterSetName = "ENABLE")]
    [Parameter(ParameterSetName = "EXTEND")]
    [Parameter(ParameterSetName = "DISABLE")]
    [String] $EnabledUsersOU = "OU=Enabled Users,OU=User Accounts,DC=theuce,DC=onmicrosoft,DC=com"
    ,
    # OU for ADMIN Users to be added to
    [Parameter(ParameterSetName = "TEST")]
    [Parameter(ParameterSetName = "NEW")]
    [Parameter(ParameterSetName = "UNLOCK")]
    [Parameter(ParameterSetName = "RESET")]
    [Parameter(ParameterSetName = "ENABLE")]
    [Parameter(ParameterSetName = "EXTEND")]
    [Parameter(ParameterSetName = "DISABLE")]
    [String] $EnabledAdminOU = "OU=Accounts,OU=Admin,DC=theuce,DC=onmicrosoft,DC=com"
    ,
    # OU for NSE Users to be added to
    [Parameter(ParameterSetName = "TEST")]
    [Parameter(ParameterSetName = "NEW")]
    [Parameter(ParameterSetName = "UNLOCK")]
    [Parameter(ParameterSetName = "RESET")]
    [Parameter(ParameterSetName = "ENABLE")]
    [Parameter(ParameterSetName = "EXTEND")]
    [Parameter(ParameterSetName = "DISABLE")]
    [String] $EnabledNSEOU = "OU=Service Accounts,OU=Admin,DC=theuce,DC=onmicrosoft,DC=com"
    ,
    # OU for Disabled Users to be added to
    [Parameter(ParameterSetName = "TEST")]
    [Parameter(ParameterSetName = "NEW")]
    [Parameter(ParameterSetName = "UNLOCK")]
    [Parameter(ParameterSetName = "RESET")]
    [Parameter(ParameterSetName = "ENABLE")]
    [Parameter(ParameterSetName = "EXTEND")]
    [Parameter(ParameterSetName = "DISABLE")]
    [String] $DisabledUsersOU = "OU=Disabled Users,OU=User Accounts,DC=theuce,DC=onmicrosoft,DC=com"
    ,
    # OU for Disabled ADMIN Accounts
    [Parameter(ParameterSetName = "TEST")]
    [Parameter(ParameterSetName = "NEW")]
    [Parameter(ParameterSetName = "UNLOCK")]
    [Parameter(ParameterSetName = "RESET")]
    [Parameter(ParameterSetName = "ENABLE")]
    [Parameter(ParameterSetName = "EXTEND")]
    [Parameter(ParameterSetName = "DISABLE")]
    [String] $DisabledAdminOU = "OU=Disabled,OU=Admin,DC=theuce,DC=onmicrosoft,DC=com"
,
    # OU for NSE Users to be added to
    [Parameter(ParameterSetName = "TEST")]
    [Parameter(ParameterSetName = "NEW")]
    [Parameter(ParameterSetName = "UNLOCK")]
    [Parameter(ParameterSetName = "RESET")]
    [Parameter(ParameterSetName = "ENABLE")]
    [Parameter(ParameterSetName = "EXTEND")]
    [Parameter(ParameterSetName = "DISABLE")]
    [String] $DisabledNSEOU = "OU=Disabled,OU=Admin,DC=theuce,DC=onmicrosoft,DC=com"
    ,
    # UPN suffix, defaults to "uce.cia.gov"
    [Parameter(ParameterSetName = "TEST")]
    [Parameter(ParameterSetName = "NEW")]
    [Parameter(ParameterSetName = "UNLOCK")]
    [Parameter(ParameterSetName = "RESET")]
    [Parameter(ParameterSetName = "ENABLE")]
    [Parameter(ParameterSetName = "EXTEND")]
    [Parameter(ParameterSetName = "DISABLE")]
    [String] $UPN = "uce.cia.gov"
    ,
    # Regular User Group Name for add, Add Users to the "UCE Users" Group to provide access to the WVD Users Host Pool
    [Parameter(ParameterSetName = "TEST")]
    [Parameter(ParameterSetName = "NEW")]
    [Parameter(ParameterSetName = "UNLOCK")]
    [Parameter(ParameterSetName = "RESET")]
    [Parameter(ParameterSetName = "ENABLE")]
    [Parameter(ParameterSetName = "EXTEND")]
    [Parameter(ParameterSetName = "DISABLE")]
    [String] $RegularUserGroup = "UCE Users"
    ,
    # UCE Admin Group Name
    [Parameter(ParameterSetName = "TEST")]
    [Parameter(ParameterSetName = "NEW")]
    [Parameter(ParameterSetName = "UNLOCK")]
    [Parameter(ParameterSetName = "RESET")]
    [Parameter(ParameterSetName = "ENABLE")]
    [Parameter(ParameterSetName = "EXTEND")]
    [Parameter(ParameterSetName = "DISABLE")]
    [String] $AdminUserGroup = "UCE Admins"
    ,
    # TAO User group
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
    ,
    # Account Expireation Date
    [Parameter(ParameterSetName = "TEST")]
    [Parameter(ParameterSetName = "NEW")]
    [Parameter(ParameterSetName = "UNLOCK")]
    [Parameter(ParameterSetName = "RESET")]
    [Parameter(ParameterSetName = "ENABLE")]
    [Parameter(ParameterSetName = "EXTEND")]
    [Parameter(ParameterSetName = "DISABLE")]
    [DateTime] $AccountExpirationDate   = ([DateTime]::Now).AddYears(1)
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

            $NewADUserProperties = [Ordered]@{
                    Name                    = $processObject.SamAccountName
                    Description             = [String]::Empty
                    SamAccountName          = $processObject.SamAccountName
                    UserPrincipalName       = ("{0}@{1}" -f $processObject.SamAccountName, $processObject.UPN)
                    DisplayName             = $processObject.SamAccountName
                    Path                    = $processObject.EnabledOU
                    Enabled                 = $true
                    AccountPassword         = (ConvertTo-SecureString $processObject.NewPassword -AsPlainText -Force)
                    ChangePasswordAtLogon   = $true
                    AccountExpirationDate   = $processObject.AccountExpirationDate
                    Confirm                 = $false
                    ErrorAction             = "Stop"
                } # $NewADUserProperties
            
            $NewUser = [PSCustomObject]@{
                            SamAccountName  = $processObject.SamAccountName
                            Created         = $false
                            ADUser          = $null
                            Enabled         = $false
                            CreatedDate     = $null
                            Exception       = $null
                        } # NewUser

            try
            {
                New-ADUser @NewADUserProperties
    
                $ADUser                 = Get-ADUser $processObject.SamAccountName -Properties whenCreated -ErrorAction Stop
                $NewUser.ADUser         = $ADUser
                $NewUser.Enabled        = $ADUser.Enabled 
                $NewUser.Created        = if($ADUser){$true}else{$false}
                $NewUser.CreatedDate    = $ADUser.whenCreated
            } # try to create new ADUser
            catch
            {
                $NewUser.Exception = $Error[0]
                Write-Warning $NewUser.Exception
            } # catch

            Write-Verbose ("{0} `t`tLeaving {1} {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)
            $NewUser
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
            try
            {
                Write-Verbose ("{0} `t`t {1} Disable-ADAccount -Identity {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)
                Disable-ADAccount -Identity $processObject.ADUser -ErrorAction Stop
                Write-Verbose ("{0} `t`t {1} Disabled {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)

                Write-Verbose ("{0} `t`t {1} Move-ADObject -Identity {2} -TargetPath {3}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName, $processObject.DisabledOU)
                Move-ADObject -Identity $processObject.ADUser -TargetPath $processObject.DisabledOU -ErrorAction Stop
                Write-Verbose ("{0} `t`t {1} Moved ({2}) from ({3}) to ({4})" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName, $processObject.OriginalOU, $processObject.DisabledOU)

            }
            catch
            {
                Write-Warning ("{0} `t`t {1} Exception {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)
            }
            <#
            Move-ADObject $adUser -TargetPath "OU=Disabled,OU=Admin,DC=theuce,DC=onmicrosoft,DC=com" -Credential $Cred -ErrorAction Stop
            Write-Output "Moved admin user $adUser to disabled OU"
            Set-ADUser $adUser.Name -Description "$Today disabled due to inactivity" -Credential $Cred -ErrorAction Stop
            #>

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
        .DESCRIPTION
        The script creates a process object with various properties to track the execution of account management tasks. 
        The process object includes information such as the computer name, username, start time, action to take, and result.

        .PARAMETER ActionToTake
        Specifies the action to be taken on the user account.
        #>

        $RunAs          = ($Env:USERNAME).ToUpper()
        $RunAsMemberOf  = (Get-ADUser $RunAs -Properties MemberOf).MemberOf

        $ADUser = try
        {
            Get-ADUser $SamAccountName -Properties * -ErrorAction Stop
        }
        catch
        {
            $null
        } # $ADUser

        $OriginalOU = if($null -eq $ADUser)
        {
            $null
        }
        else
        {
            $Split = $ADUser.DistinguishedName.Split(",") 
            ($Split | Select-Object -Last ($Split.Count-1)) -Join ","
        }

        $processObject = [PSCustomObject]@{
            RunOn                   = ($Env:COMPUTERNAME).ToUpper()
            RunAs                   = $RunAs
            RunAsMemberOf           = $RunAsMemberOf
            Begin                   = ([DateTime]::Now)
            # Change SamAccountName to lower then Title Case and reassign to SamAccountName (for when Name is all CAPS)
            SamAccountName          = (Get-Culture).TextInfo.ToTitleCase($SamAccountName.ToLower()) 
            TypeOfUser              = $null
            ActionToTake            = $ActionToTake
            ADUser                  = $ADUser
            OriginalOU              = $OriginalOU
            # Enabled and Disabled to be set based on type of account
            EnabledOU               = $null
            DisabledOU              = $null

            End                     = $null
            Duration                = $null
            Message                 = "No Action Taken"
            Results                 = $null
            NewPassword             = New-Password
            # Standard and Test Users
            EnabledUsersOU          = $EnabledUsersOU
            DisabledUsersOU         = $DisabledUsersOU
            # Admin Users
            EnabledAdminOU          = $EnabledAdminOU
            DisabledAdminOU         = $DisabledAdminOU
            # NSE Users
            EnabledNSEOU            = $EnabledNSEOU
            DisabledNSEOU           = $DisabledNSEOU

            UPN                     = $UPN
            RegularUserGroup        = $RegularUserGroup
            AdminUserGroup          = $AdminUserGroup
            GroupsToAddTo           = [System.Collections.ArrayList]::new()
            TAOGroup                = $TAOGroup
            AzureActiveDirectoryVM  = $AzureActiveDirectoryVM
            OnSiteOnlyProperty      = $OnSiteOnlyProperty
            OnSiteOnlyValue         = $null
            OnSiteOnly              = $true
            AccountExpirationDate   = $AccountExpirationDate
            Exception               = $null
        } # $processObject


        <#
        .DESCRIPTION
        This code block assigns a value to the $processObject.TypeOfUser variable based on the SamAccountName suffix. 
        If the SamAccountName ends with "-ADM", the type of user is set to "ADM". 
        If it ends with "-TST", the type of user is set to "TEST". 
        If it ends with "-NSE", the type of user is set to "NSE". 
        For any other suffix, the type of user is set to "STANDARD".

        .PARAMETER processObject
        The object representing the user being processed.

        .OUTPUTS
        The type of user assigned to the $processObject.TypeOfUser variable.
        #>


        if($processObject.SamAccountName.EndsWith("-ADM"))
        {
            $processObject.TypeOfUser   = "ADM"
            $processObject.EnabledOU    = $processObject.EnabledAdminOU
            $processObject.DisabledOU   = $processObject.DisabledAdminOU
            [void] $processObject.GroupsToAddTo.Add($AdminUserGroup)
        } # ADM
        elseif($processObject.SamAccountName.EndsWith("-TST"))
        {
            $processObject.TypeOfUser   = "TEST"
            $processObject.EnabledOU    = $processObject.EnabledUsersOU
            $processObject.DisabledOU   = $processObject.DisabledUsersOU
            [void] $processObject.GroupsToAddTo.Add($RegularUserGroup)
        } # TST
        elseif($processObject.SamAccountName.EndsWith("-NSE"))
        {
            $processObject.TypeOfUser   = "NSE"
            $processObject.EnabledOU    = $processObject.EnabledNSEOU
            $processObject.DisabledOU   = $processObject.DisabledNSEOU
            [void] $processObject.GroupsToAddTo.Add($RegularUserGroup)
        } # NSE
        else
        {
            $processObject.TypeOfUser   = "STANDARD"
            $processObject.EnabledOU    = $processObject.EnabledUsersOU
            $processObject.DisabledOU   = $processObject.DisabledUsersOU
            [void] $processObject.GroupsToAddTo.Add($RegularUserGroup)
        } # Default type of user to STANDARD


        <#
        .DESCRIPTION
            This code block attempts to retrieve an Active Directory user object using the Get-ADUser cmdlet.
            If the user is found, the user object is assigned to the $processObject.ADUser variable.
            If the user is not found, the string "NOT FOUND" is assigned to the $processObject.ADUser variable.

        .PARAMETER SamAccountName
            The SamAccountName of the user to retrieve.

        .OUTPUTS
            Microsoft.ActiveDirectory.Management.ADUser
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


        switch ($processObject.ActionToTake)
        {
            "DISABLE"   {
                $action = "DISABLE"
                $target = $processObject.SamAccount
                if($PSCmdlet.ShouldProcess($action,$target))
                {
                    $processObject.Results = Disable-User -processObject $processObject
                } # Disable-User
                else
                {
                    $processObject.Results = ("WhatIf for Disable-User ({0})" -f $processObject.SamAccountName)
                } # Whatif for Disable-User
            } # DISABLE
            "EXTEND"    {
                $action = "EXTEND"
                $target = $processObject.SamAccount
                if($PSCmdlet.ShouldProcess($action,$target))
                {
                    $processObject.Results = Update-User -processObject $processObject
                } # Update-User
                else
                {
                    $processObject.Results = ("WhatIf for Update-User ({0})" -f $processObject.SamAccountName)
                } # Whatif for Update-User
            } # EXTEND (UPDATE)
            "ENABLE"    {
                $action = "ENABLE"
                $target = $processObject.SamAccount
                if($PSCmdlet.ShouldProcess($action,$target))
                {
                    $processObject.Results = Enable-User -processObject $processObject
                } # Enable-User
                else
                {
                    $processObject.Results = ("WhatIf for Enable-User ({0})" -f $processObject.SamAccountName)
                } # Whatif for Enable-User
            } # ENABLE
            "NEW"       {
                $action = "NEW"
                $target = $processObject.SamAccount
                if($PSCmdlet.ShouldProcess($action,$target))
                {
                    $processObject.Results = New-User -processObject $processObject
                } # New-User
                else
                {
                    $processObject.Results = ("WhatIf for New-User ({0})" -f $processObject.SamAccountName)
                } # Whatif for New-User
            } # NEW
            "RESET"     {
                $action = "RESET"
                $target = $processObject.SamAccount
                if($PSCmdlet.ShouldProcess($action,$target))
                {
                    $processObject.Results = Reset-User -processObject $processObject
                } # Reset-User
                else
                {
                    $processObject.Results = ("WhatIf for Reset-User ({0})" -f $processObject.SamAccountName)
                } # Whatif for Reset-User
            } # RESET
            "UNLOCK"    {
                $action = "UNLOCK"
                $target = $processObject.SamAccount
                if($PSCmdlet.ShouldProcess($action,$target))
                {
                    $processObject.Results = Unlock-User -processObject $processObject
                } # Unlock-User
                else
                {
                    $processObject.Results = ("WhatIf for Unlock-User ({0})" -f $processObject.SamAccountName)
                } # Whatif for Unlock-User
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

        $target = $AzureActiveDirectoryVM
        $action = "Start-ADSyncSyncCycle"
        if($PSCmdlet.ShouldProcess($target,$action))
        {
            Write-Verbose ("{0} BEGIN ({1}) on ({2})" -f [DateTime]::Now, $action, $AzureActiveDirectoryVM)

            try
                {
                    # Synchronize AD with AzureAD
                    $ScriptBlock = {
                        try
                        {
                            Import-Module ADSync -ErrorAction Stop
                            $ADSyncSyncResults = Start-ADSyncSyncCycle -PolicyType Delta -ErrorAction Stop

                            [PSCustomObject]@{
                                ADSyncSyncResults   = $ADSyncSyncResults
                            } # Custom Object to return
                        } # try
                        catch
                        {
                            [PSCustomObject]@{
                                ADSyncSyncResults   = $Error[0]
                            } # Custom Object to Return
                        } # catch
                    } # $ScriptBlock

                    $SyncResults = Invoke-Command -ScriptBlock $ScriptBlock -ComputerName $AzureActiveDirectoryVM -ErrorAction Stop -HideComputerName
                    Write-Verbose ("{0} Active Directory SyncResults ({1}) from ({2})" -f [DateTime]::Now, $SyncResults.ADSyncSyncResults.Result, $AzureActiveDirectoryVM)
                } # try Invoke on vm
                catch
                {
                    Write-Warning ($Error[0].Exception.Message)
                }
            Write-Verbose ("{0} END ({1}) on ({2})" -f [DateTime]::Now, $action, $AzureActiveDirectoryVM)
        } # ShouldProcess Start-ADDSyncCycle

    Write-Verbose ("{0} Leaving EndProccessing {1}" -f [DateTime]::Now, $MyInvocation.MyCommand.Name)
    # Retun the collection of Users Processed to the pipeline
    $UsersProcessed
} # end
