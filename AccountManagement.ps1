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

    .PARAMETER AccountExpirationDate
        Account Expiration Date

    .PARAMETER Force
        Force Switch to send all object properties to the pipeline

    .PARAMETER ADSync
        ADSync switch to Start-ADSyncSyncCycle
    
    .EXAMPLE
        .\AccountManagement.ps1 -SamAccountName "jsmith" -TEST -Verbose -WhatIf
        Tests the user account for specific properties

    .EXAMPLE
        "TestUser", "TestUser-NSE", "TestUser-NSE", "TestUser-ADM" | .\AccountManagement.ps1 -TEST -Verbose -WhatIf

    .EXAMPLE
        "TestUser20240229" | .\AccountManagement.ps1 -TEST -Verbose -WhatIf

    .EXAMPLE
        "TestUser20240229" | .\AccountManagement.ps1 -NEW -Verbose -Force

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
    [DateTime] $AccountExpirationDate   = (([DateTime]::Now).AddYears(1))
    ,
    # Force Switch to send all object properties to the pipeline
    [Parameter(ParameterSetName = "TEST")]
    [Parameter(ParameterSetName = "NEW")]
    [Parameter(ParameterSetName = "UNLOCK")]
    [Parameter(ParameterSetName = "RESET")]
    [Parameter(ParameterSetName = "ENABLE")]
    [Parameter(ParameterSetName = "EXTEND")]
    [Parameter(ParameterSetName = "DISABLE")]
    [Switch] $Force
    ,
    # ADSync switch to Start-ADSyncSyncCycle
    [Parameter(ParameterSetName = "NEW")]
    [Parameter(ParameterSetName = "UNLOCK")]
    [Parameter(ParameterSetName = "RESET")]
    [Parameter(ParameterSetName = "ENABLE")]
    [Parameter(ParameterSetName = "EXTEND")]
    [Parameter(ParameterSetName = "DISABLE")]
    [Switch] $ADSync

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

                $ADUser                 = Get-ADUser $processObject.SamAccountName -Properties * -ErrorAction Stop
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
            try
            {

                $FunctionName = "Unlock-User"
                Write-Verbose ("{0} `t`tEntering {1} {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)
    
                $UnlockedUser = [PSCustomObject]@{
                    ADUser      = (Get-ADuser -Identity $processObject.SamAccountName)
                    Exception = $null
                } # $UnlockedUser

                # Unlock account
                Write-Verbose ("{0} `t`t`t {1} : Unlock ({2})" -f [DateTime]::Now, $FunctionName, $UnlockedUser.ADUser.UserPrincipalName)
                Unlock-ADAccount -Identity $processObject.SamAccountName -ErrorAction Stop
                # Update info collection value
                $processObject.UpdatedInfo          = ($processObject.OriginalInfo + ("{0:yyyy-MM-dd HH:mm:ss} Account Unlocked" -f [DateTime]::Now))
                # Update the ASUser info with new values
                $UnlockedUser.ADUser | Set-ADUser -Replace @{info = $processObject.UpdatedInfo}
            } # try
            catch
            {
                $UnlockedUser.Exception = $_
                Write-Warning $UnlockedUser.Exception
            } # catch

            Write-Verbose ("{0} `t`tLeaving {1} {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)
            $UnlockedUser
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
            try
            {
                $FunctionName = "Reset-User"
                Write-Verbose ("{0} `t`tEntering {1} {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)
                $ResetUser = [PSCustomObject]@{
                        ADUser          = (Get-ADuser $processObject.SamAccountName -Properties *)
                        Message         = $null
                        Exception       = $null
                } # $ResetUser Custom Object

                # Enable Account
                Write-Verbose ("{0} `t`t`t {1} : Account Enabled" -f [DateTime]::Now, $FunctionName)
                Enable-ADAccount -Identity $processObject.SamAccountName -ErrorAction Stop
                $ResetUser.Message = ("`n{0:yyyy-MM-dd HH:mm:ss} Account Enabled" -f [DateTime]::Now)

                # Assign new password for account
                Write-Verbose ("{0} `t`t`t {1} : Assign new password to ({2})" -f [DateTime]::Now, $FunctionName,$ResetUser.ADUser.UserPrincipalName)
                $ResetUser.ADUser | Set-ADAccountPassword -NewPassword (ConvertTo-SecureString -String $processObject.NewPassword -AsPlainText -Force) -Reset
                $ResetUser.Message = $ResetUser.Message + ("`n{0:yyyy-MM-dd HH:mm:ss} New Password Assigned" -f [DateTime]::Now)

                # Unlock account
                Write-Verbose ("{0} `t`t`t {1} : Unlock ({2})" -f [DateTime]::Now, $FunctionName,$ResetUser.ADUser.UserPrincipalName)
                Unlock-ADAccount -Identity $processObject.SamAccountName -ErrorAction Stop
                $ResetUser.Message = $ResetUser.Message + ("`n{0:yyyy-MM-dd HH:mm:ss} Account Unlocked" -f [DateTime]::Now)

                # Move account to Correct OU
                Write-Verbose ("{0} `t`t`t {1} : Move ({2}) to ({3})" -f [DateTime]::Now, $FunctionName, $ResetUser.ADUser.UserPrincipalName, $processObject.EnabledOU)
                Move-ADObject -Identity $ResetUser.ADUser -TargetPath $processObject.EnabledOU -ErrorAction Stop
                $ResetUser.Message = $ResetUser.Message + ("`n{0:yyyy-MM-dd HH:mm:ss} Account Moved to {1}" -f [DateTime]::Now, $processObject.EnabledOU)

                # Update account Expiration Date
                Write-Verbose ("{0} `t`t`t {1} : Update Expiration Date for ({2}) to ({3})" -f [DateTime]::Now, $FunctionName,$ResetUser.ADUser.UserPrincipalName, $processObject.AccountExpirationDate)
                Set-ADAccountExpiration -Identity $processObject.SamAccountName -DateTime $processObject.AccountExpirationDate
                $ResetUser.Message = $ResetUser.Message + ("`n{0:yyyy-MM-dd HH:mm:ss} Account Expiration updated to {1}" -f [DateTime]::Now, $processObject.AccountExpirationDate)

                # Update the Account Information Property
                Write-Verbose ("{0} `t`t`t {1} : Update Account info property for ({2})" -f [DateTime]::Now, $FunctionName, $ResetUser.ADUser.UserPrincipalName )
                $ResetUser.ADUser | Set-ADUser -Replace @{info = ($ResetUser.ADUser.info + $ResetUser.Message)}

                # Refresh the properties for the Active Directory User
                Write-Verbose ("{0} `t`t`t {1} : Refresh the Active Directiry User properties for ({2})" -f [DateTime]::Now, $FunctionName, $ResetUser.ADUser.UserPrincipalName)
                $ResetUser.ADUser = (Get-ADuser $processObject.SamAccountName -Properties *)
            } # try
            catch
            {
                $ResetUser.Exception = $_
                Write-Warning $ResetUser.Exception
            } # catch
            Write-Verbose ("{0} `t`tLeaving {1} {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)

            $ResetUser.ADUser = (Get-ADuser $processObject.SamAccountName -Properties *)
            $ResetUser
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
            try
            {
                $FunctionName = "Enable-User"
                Write-Verbose ("{0} `t`tEntering {1} {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)

                $EnabledUser = [PSCustomObject]@{
                    ADUser          = (Get-ADuser $processObject.SamAccountName -Properties *)
                    OU              = $null
                    EnabledOU       = $processObject.EnabledOU
                    InExpectedOU    = $false
                    Message         = $null
                    Exception       = $null
                } # $EnabledUser

                Write-Verbose ("{0} `t`t {1} Enable-ADAccount -Identity {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)
                Enable-ADAccount -Identity $processObject.SamAccountName -ErrorAction Stop
                Write-Verbose ("{0} `t`t {1} Enabled {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)

                Write-Verbose ("{0} `t`t {1} Move-ADObject -Identity {2} -TargetPath {3}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName, $processObject.EnabledOU)
                Move-ADObject -Identity $EnabledUser.ADUser -TargetPath $processObject.EnabledOU -ErrorAction Stop
                Write-Verbose ("{0} `t`t {1} Moved ({2}) from ({3}) to ({4})" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName, $processObject.OriginalOU, $processObject.EnabledOU)


                $EnabledUser.ADUser = try
                                    {
                                        Get-ADUser $processObject.SamAccountName -Properties *
                                    }
                                    catch
                                    {
                                        Write-Warning ("Issue getting ADUser")
                                        $null
                                    } # $EnabledUser.ADUser

                if($EnabledUser.ADUser)
                {
                    $Split                      = ($EnabledUser.ADUser.DistinguishedName.Split(","))
                    $EnabledUser.OU             = (($Split | Select-Object -Last ($Split.Count-1)) -Join ",")
                    $EnabledUser.InExpectedOU   = ($EnabledUser.DisabledOU -eq  $EnabledUser.OU)
                    $EnabledUser.Message        = ("`n{0:yyyy-MM-dd HH:mm:ss} Account Enabled" -f [DateTime]::Now)
                    $EnabledUser.ADUser | Set-ADUser -Replace @{info = ($EnabledUser.ADUser.info + $EnabledUser.Message)}
                } # ADUser found
                else
                {
                    $EnabledUser.Exception     = ("{0} Not found" -f $processObject.SamAccountName)
                } # User not found
            } # try
            catch
            {
                $EnabledUser.Exception = ("{0} `t`t {1} Exception {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)
                Write-Warning $EnabledUser.Exception
            } # catch

            Write-Verbose ("{0} `t`tLeaving {1} {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)
            $EnabledUser
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

                $DisabledUser = [PSCustomObject]@{
                    ADUser          = $null
                    OU              = $null
                    DisabledOU      = $processObject.DisabledOU
                    InExpectedOU    = $false
                    Message         = $null
                    Exception       = $null
                } # $DisabledUser

                $DisabledUser.ADUser = Get-ADUser $processObject.SamAccountName -Properties *

                if($DisabledUser.ADUser)
                {
                    $Split                      = ($DisabledUser.ADUser.DistinguishedName.Split(","))
                    $DisabledUser.OU            = (($Split | Select-Object -Last ($Split.Count-1)) -Join ",")
                    $DisabledUser.InExpectedOU  = ($DisabledUser.DisabledOU -eq  $DisabledUser.OU)
                    $DisabledUser.Message       = ("`n{0:yyyy-MM-dd HH:mm:ss} Account Disabled" -f [DateTime]::Now)
                    $DisabledUser.ADUser | Set-ADUser -Replace @{info = ($DisabledUser.ADUser.info + $DisabledUser.Message)}
                } # ADUser found
                else
                {
                    $DisabledUser.Exception     = ("{0} Not found" -f $processObject.SamAccountName)
                } # User not found
            } # try
            catch
            {
                $DisabledUser.Exception = ("{0} `t`t {1} Exception {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)
                Write-Warning $DisabledUser.Exception
            }
            Write-Verbose ("{0} `t`tLeaving {1} {2}" -f [DateTime]::Now, $FunctionName, $processObject.SamAccountName)
            $DisabledUser
        } # process
    } # function Disable-User

    function Get-AccountInfoForUpdate
    {
        <#
            .SYNOPSIS
                The Active Directory User info property can hold 1024 characters
                This function returns a string of the most recent entries with length -le 1024
        #>
        [CmdletBinding()]
        param
        (
            # Current contents from the ADUser info property
            [Parameter()]
            [String] $CurrentInfo
            ,
            # Info to add for current action
            [Parameter()]
            [String] $InfoToAdd
            ,
            # Maximum characters allowed to return
            [Parameter()]
            [Int] $MaxCharacterLength = 1024
            ,
            # Lines to Keep for the info
            [Parameter()]
            [Int] $LineToKeep = 5
        )
        process
        {
            $FunctionName = "Get-AccountInfoForUpdate"
            Write-Verbose ("{0} `t`tEntering {1}" -f [DateTime]::Now, $FunctionName)

            Write-Verbose ("{0} `t`t`tCurrent info value is ({1}) characters long" -f [DateTime]::Now, $CurrentInfo.Length)
            Write-Verbose ("{0} `t`t`tCurrent info value is (`n{1}`n)" -f [DateTime]::Now, $CurrentInfo)
            $CurrentInfoCollection = $CurrentInfo.Split("`n")
            Write-Verbose ("{0} `t`t`tCurrent info has ({1}) lines of information" -f [DateTime]::Now, $CurrentInfoCollection.Count)

            Write-Verbose ("{0} `t`t`tInfo to add value is ({1}) characters long" -f [DateTime]::Now, $InfoToAdd.Length)
            Write-Verbose ("{0} `t`t`tInfo to add value is (`n{1}`n)" -f [DateTime]::Now, $InfoToAdd)
            $InfoToAddCollection = $InfoToAdd.Split("`n")
            Write-Verbose ("{0} `t`t`tInfo to add has ({1}) lines of information" -f [DateTime]::Now, $InfoToAddCollection.Count)

            Write-Verbose ("{0} `t`t`tMax Characters allowed ({1})" -f [DateTime]::Now, $MaxCharacterLength)
            $NewLength = $CurrentInfo.Length + $InfoToAdd.Length + 2 # 2 is for the `n
            Write-Verbose ("{0} `t`t`tCombined Length ({1})" -f [DateTime]::Now, $NewLength)
            
            if($NewLength -gt $MaxCharacterLength)
            {
                Write-Verbose ("{0} `t`t`tThe length of the combined string ({1}) is greater than the Max Characters allowed ({2})" -f [DateTime]::Now, $NewLength, $MaxCharacterLength)
                $NewInfo =  if ($InfoToAdd.Length -gt $MaxCharacterLength)
                            {
                                $IndexToSelect = ($MaxCharacterLength-1)
                                Write-Verbose ("{0} `t`t`tCharacters to select ({1})" -f [DateTime]::Now, $IndexToSelect)
                                ($InfoToAdd.ToCharArray()[0..$IndexToSelect]) -join ""
                            } # ($InfoToAdd.Length -gt $MaxCharacterLength)
                            else 
                            {
                                $IndexToSelect = ($MaxCharacterLength - $InfoToAdd.Length - 2)
                                Write-Verbose ("{0} `t`t`tCharacters to select ({1})" -f [DateTime]::Now, $IndexToSelect)

                                $InfoToAdd + "`n" + (($CurrentInfo.ToCharArray()[0..$IndexToSelect]) -join "")
                            } # else add NewInfo with part of CurrentInfo
            } # if($NewLength -gt $MaxCharacterLength)
            else
            {
                Write-Verbose ("{0} `t`t`tThe length of the combined string ({1}) is less than the Max Characters allowed ({2})" -f [DateTime]::Now, $NewLength, $MaxCharacterLength)
                $NewInfo = $CurrentInfo + "`n" + $InfoToAdd
            } # Not ($NewLength -gt $MaxCharacterLength)
            Write-Verbose ("{0} `t`tLeaving {1}" -f [DateTime]::Now, $FunctionName)
            # Return NewInfo to the pipeline
            $NewInfo
        } # process
    } # function Get-AccountInfoForUpdate
    <# 
        Get-AccountInfoForUpdate -CurrentInfo $CurrentInfo -InfoToAdd $CurrentInfo -Verbose 
    #>

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
        # Get the Action to take based on the ParameterSetName
        $ActionToTake = ($PSCmdlet.ParameterSetName.ToUpper())

        # Get the Runas user and the groups the user is a member of
        $RunAs          = ($Env:USERNAME).ToUpper()
        $RunAsMemberOf  = (Get-ADUser $RunAs -Properties MemberOf).MemberOf

        # Get the Active Directory User object if the account exists
        $ADUser =   try
                    {
                        Get-ADUser $SamAccountName -Properties * -ErrorAction Stop
                    }
                    catch
                    {
                        $null
                    } # $ADUser

        # Get the Original Information for the user
        $OriginalInfo = if($null -eq $ADUser)
                        {
                            $null
                        } # if($null -eq $ADUser)
                        else
                        {
                            $ADUser.Info
                        } # $OriginalInfo

        # Get the Original OU for the user
        $OriginalOU     = if($null -eq $ADUser)
                        {
                            $null
                        } # if($null -eq $ADUser)
                        else
                        {
                            # Get the DistinguishedName and split it into an array
                            $Split = $ADUser.DistinguishedName.Split(",")
                            # Join the last elements (excluding the first element) of the array to get the Original OU
                            ($Split | Select-Object -Last ($Split.Count-1)) -Join ","
                        } # $OriginalOU

        # Get the UserPrincipalName for the user
        $UserPrincipalName = if($null -eq $ADUser)
                        {
                            $null
                        } # if($null -eq $ADUser)
                        else
                        {
                            $ADUser.UserPrincipalName
                        } # $UserPrincipalName

        # Create a new object to hold the process information
        $processObject = [PSCustomObject]@{
            # RunOn is the computer the script is running on
            RunOn                   = ($Env:COMPUTERNAME).ToUpper()
            # RunAs is the user running the script
            RunAs                   = $RunAs
            # RunAsMemberOf is the groups the user is a member of
            RunAsMemberOf           = $RunAsMemberOf
            # Begin is the time the process started
            Begin                   = ([DateTime]::Now)
            # Change SamAccountName to lower then Title Case and reassign to SamAccountName (for when Name is all CAPS)
            SamAccountName          = (Get-Culture).TextInfo.ToTitleCase($SamAccountName.ToLower())
            # UserPrincipalName is the email address for the user
            UserPrincipalName       = $UserPrincipalName
            # TypeOfUser is the type of user based on the SamAccountName suffix
            TypeOfUser              = $null
            # ActionToTake is the action to take based on the ParameterSetName
            ActionToTake            = $ActionToTake
            # ADUser is the Active Directory User object
            ADUser                  = $ADUser
            # OriginalOU is the original OU for the user
            OriginalOU              = $OriginalOU
            # OriginalInfo is the Telephones Notes: limited to 1024 characters, keep last 5 lines
            OriginalInfo            = $OriginalInfo
            # UpdatedInfo is the updated Telephones Notes: limited to 1024 characters, keep last 5 lines
            UpdatedInfo             = $null
            # EnabledOU to be set based on type of account
            EnabledOU               = $null
            # DisabledOU to be set based on type of account
            DisabledOU              = $null
            # End is the time the process ended
            End                     = $null
            # Duration is the time the process took
            Duration                = $null
            # Message is the result of the process
            Message                 = "No Action Taken"
            # Results is the result of the process
            Results                 = $null
            # NewPassword is the new password for the user
            NewPassword             = New-Password
            # Enabled OU for Standard and Test Users
            EnabledUsersOU          = $EnabledUsersOU
            # Disabled OU for Standard and Test Users
            DisabledUsersOU         = $DisabledUsersOU
            # Enabled OU for Admin Users
            EnabledAdminOU          = $EnabledAdminOU
            # Disabled OU for Admin Users
            DisabledAdminOU         = $DisabledAdminOU
            # Enabled OU for NSE Users
            EnabledNSEOU            = $EnabledNSEOU
            # Disabled OU for NSE Users
            DisabledNSEOU           = $DisabledNSEOU
            # UPN is the User Principal Name suffix
            UPN                     = $UPN
            # RegularUserGroup is the group to add regular users to
            RegularUserGroup        = $RegularUserGroup
            # AdminUserGroup is the group to add admin users to
            AdminUserGroup          = $AdminUserGroup
            # GroupsToAddTo is the groups to add the user to
            GroupsToAddTo           = [System.Collections.ArrayList]::new()
            # TAOGroup is the group to add the user to if needed
            TAOGroup                = $TAOGroup
            # AzureActiveDirectoryVM is the Azure Active Directory VM
            AzureActiveDirectoryVM  = $AzureActiveDirectoryVM
            # OnSiteOnlyProperty is the property to set for OnSiteOnly
            OnSiteOnlyProperty      = $OnSiteOnlyProperty
            # OnSiteOnlyValue is the value to set for OnSiteOnly
            OnSiteOnlyValue         = $null
            # OnSiteOnly is the property to set for OnSiteOnly
            OnSiteOnly              = $true
            # AccountExpirationDate is the date the account will expire
            AccountExpirationDate   = $AccountExpirationDate
            # Exception is the exception that occurred
            Exception               = $null
        } # $processObject

        # Set TypeOfUser, EnabledOU, DisabledOU, and GroupsToAddTo based on the SamAccountName suffix
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

        # Verify ADUser is not null
        $processObject.ADUser = $(
                                    try
                                    {
                                        Get-ADUser $processObject.SamAccountName -Properties *
                                    } # try
                                    catch
                                    {
                                        "NOT FOUND"
                                    } # catch
                                ) # $processObject.ADUser

        # Set the UserPrincipalName based on the ADUser, if present
        $processObject.UserPrincipalName = if($null -eq $processObject.ADUser)
                                    {
                                        $null
                                    } # if($null -eq $processObject.ADUser)
                                    else
                                    {
                                        $processObject.ADUser.UserPrincipalName
                                    } # $processObject.UserPrincipalName

        <#
            This switch statement executes different actions based on the value of $processObject.ActionTake.
            The available actions are: DISABLE, EXTEND, ENABLE, NEW, RESET, UNLOCK. If none of these actions match,
            it will call the Test-User function with $processObject as a parameter.
        #>

        switch ($processObject.ActionToTake)
        {
            "DISABLE"   {
                $action = "DISABLE"
                $target = $processObject.SamAccountName
                if($PSCmdlet.ShouldProcess($target,$action))
                {
                    $DisabledUser               = Disable-User -processObject $processObject
                    $processObject.Results      = if($DisabledUser.Enabled){$false}else{$true}
                    $processObject.UpdatedInfo  = $DisabledUser.info
                } # Disable-User
                else
                {
                    $processObject.Results = ("WhatIf for Disable-User ({0})" -f $processObject.SamAccountName)
                } # Whatif for Disable-User
            } # DISABLE
            "EXTEND"    {
                $action = "EXTEND"
                $target = $processObject.SamAccountName
                if($PSCmdlet.ShouldProcess($target,$action))
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
                $target = $processObject.SamAccountName
                if($PSCmdlet.ShouldProcess($target,$action))
                {
                    $EnabledUser                = Enable-User -processObject $processObject
                    $processObject.UpdatedInfo  = $EnabledUser.info
                } # Enable-User
                else
                {
                    $processObject.Results = ("WhatIf for Enable-User ({0})" -f $processObject.SamAccountName)
                } # Whatif for Enable-User
            } # ENABLE
            "NEW"       {
                $action = "NEW"
                $target = $processObject.SamAccountName
                if($PSCmdlet.ShouldProcess($target,$action))
                {
                    $NewUser = New-User -processObject $processObject
                    if($NewUser.Created)
                    {
                        $processObject.Results              = ("({0}) created" -f $NewUser.SamAccountName)
                        $processObject.ADUser               = $NewUser.ADUser
                        $processObject.UserPrincipalName    = $NewUser.ADUser.UserPrincipalName
                        $processObject.UpdatedInfo          = ($processObject.OriginalInfo + ("{0:yyyy-MM-dd HH:mm:ss} Account Created" -f [DateTime]::Now))
                        $NewUser.ADUser | Set-ADUser -Replace @{info = $processObject.UpdatedInfo}
                    } # NewUser created
                    else
                    {
                        $processObject.Results      = ("({0}) Not created)" -f $NewUser.SamAccountName)
                        $processObject.Exception    = $NewUser.Exception
                    } # # NewUser Not created
                } # New-User
                else
                {
                    $processObject.Results = ("WhatIf for New-User ({0})" -f $processObject.SamAccountName)
                } # Whatif for New-User
            } # NEW
            "RESET"     {
                $action = "RESET"
                $target = $processObject.SamAccountName
                if($PSCmdlet.ShouldProcess($target,$action))
                {
                    $ResetUser                          = Reset-User -processObject $processObject
                    $processObject.Results              = ("({0}) Reset" -f $NewUser.SamAccountName)
                    $processObject.ADUser               = $ResetUser.ADUser
                    $processObject.UserPrincipalName    = $ResetUser.ADUser.UserPrincipalName
                    $processObject.UpdatedInfo          = $ResetUser.ADUser.info
                } # Reset-User
                else
                {
                    $processObject.Results = ("WhatIf for Reset-User ({0})" -f $processObject.SamAccountName)
                } # Whatif for Reset-User
            } # RESET
            "UNLOCK"    {
                $action = "UNLOCK"
                $target = $processObject.SamAccountName
                if($PSCmdlet.ShouldProcess($target,$action))
                {
                    $UnlockedUser           = Unlock-User -processObject $processObject
                    $processObject.Results  = $UnlockedUser.Message

                    $processObject.Results              = ("({0}) Unlocked" -f $NewUser.SamAccountName)
                    $processObject.ADUser               = $UnlockedUser.ADUser
                    $processObject.UserPrincipalName    = $UnlockedUser.ADUser.UserPrincipalName
                    $processObject.UpdatedInfo          = ($processObject.OriginalInfo + ("{0:yyyy-MM-dd HH:mm:ss} Account Unlocked" -f [DateTime]::Now))
                    $UnlockedUser.ADUser | Set-ADUser -Replace @{info = $processObject.UpdatedInfo}

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
        if($PSBoundParameters.ContainsKey("Force"))
        {
            Write-Verbose ("{0}`t`tForce switch sent, adding all properties to pipeline" -f [DateTime]::Now)
            [void] $UsersProcessed.Add($processObject)
        } # If Force all propeties
        else
        {
            Write-Verbose ("{0}`t`tForce switch Not present, sending default properties" -f [DateTime]::Now)
            [void] $UsersProcessed.Add($($processObject | Select-Object SamAccountName, NewPassword, UserPrincipalName, Message))
        } # Default properties to minimize output
    } # try
    catch
    {
        # Set the Exception property to the exception that occurred
        $processObject.Exception = $Error[0].Exception
        Write-Error ("{0} EXCEPTION : ({1})" -f [DateTime]::Now, $processObject.Exception)
    } # catch
    finally
    {
        # Set the End and Duration properties
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

        if($PSBoundParameters.ContainsKey("ADSync"))
        {
            Write-Verbose ("{0} `t ADSync Switch present, process for ({1}) on ({2})" -f [DateTime]::Now, $action, $AzureActiveDirectoryVM)

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
        } # if($PSBoundParameters.ContainsKey("ADSync"))
    Write-Verbose ("{0} Leaving EndProccessing {1}" -f [DateTime]::Now, $MyInvocation.MyCommand.Name)
    # Retun the collection of Users Processed to the pipeline
    $UsersProcessed
} # end