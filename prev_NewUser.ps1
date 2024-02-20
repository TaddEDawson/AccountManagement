function Get-CurrentLine
{
    $MyInvocation.ScriptLineNumber  
}
function New-UCEADUser
{
    <#
        .SYNOPSIS
            Create UCE user and add to appropriate OUs for permissions
        .NOTES
            Object being passed from New-UCEUser, accounts need same EmployeeID and base account name
        .EXAMPLE
            $UserToCreate.AccountName
            $UserToCreate.Password
            $UserToCreate | New-UCEADUser -WhatIf -Verbose
        .EXAMPLE
            # Shortcut for testing via custom object
            $UserToCreate = [PSCustomObject]@{
                ID = 1234567
                AccountName = "Zz_Test1234567"
                WVDOnly=$False
                OnSiteOnly=$False
                MDM=$True
                TAO=$True
                PassWord                ='#M#nE3@fH8#3hU'
                TemporaryAccessPass     = [String]::Empty
                ProcessedDate="07/05/2022 09:54:00" 
                Created=$False
                CreatedDate=$null 
                UserOfTypeExists=$False
                OKtoCreate=$True
                Type="Regular"
                Notes="Regular User for (Zz_TEST1234567) with EmployeeID (1234567) does not exist"
            }   
            
            Get-ADUser Zz_TEST1234567 | Remove-ADUser

            $UserToCreate | New-UCEADUser -Verbose -Confirm
        .EXAMPLE
            # Goal : 

    #>
    [CmdletBinding(
        SupportsShouldProcess
    )]
    param
    (
        # Object from pipeline
        [Parameter(
            ValueFromPipeline,
            ValueFromPipelineByPropertyName
        )]
        $UserToCreate
        ,
        # OU for user to be added to
        [Parameter()]
        [String]
        $EnabledUsersOU = "OU=Enabled Users,OU=User Accounts,DC=theuce,DC=onmicrosoft,DC=com"
        ,
        # OU for ADMIN Users to be added to
        [Parameter()]
        [String]
        $AdminOU = "OU=Accounts,OU=Admin,DC=theuce,DC=onmicrosoft,DC=com"
        ,
        # UPN suffix, defaults to "uce.cia.gov"
        [Parameter()]
        [String]
        $UPN = "uce.cia.gov"
        ,
        # Regular User Group Name for add, Add Users to the "UCE Users" Group to provide access to the WVD Users Host Pool
        [Parameter()]
        [String]
        $RegularUserGroup = "UCE Users"
        ,
        # UCE Admin Group Name
        [Parameter()]
        [String]
        $AdminUserGroup = "UCE Admins"
        ,
        # TAO User group
        [Parameter()]
        [String] $TAOGroup = "TAO Users"
        ,
        #  $AzureActiveDirectoryVM
        [Parameter()]
        [String] $AzureActiveDirectoryVM = "uce-adc-vm-2"
        ,
        # TenantID for MgGraph connection
        [Parameter()]
        [String] $TenantID = "2fe98fc3-3118-4542-bc7a-15c254cc5a32"
    )# param
    process
    {
        if($_)
        {
            Write-Verbose ("{0} something in the pipeline, assigning to UserToCreate"  -f $(Get-CurrentLine))
            Write-Verbose ("{0} ({1})"  -f $(Get-CurrentLine), $($_))
            $UserToCreate = $_
        }
        
        if($PSCmdlet.ShouldProcess($UserToCreate.AccountName))
        {
            try
            {
                $GroupsToAddTo = [System.Collections.ArrayList]::New()

                Switch ($UserToCreate.Type)
                {
                    "Admin"     {
                                    Write-Verbose ("{0} Creating ADM Account" -f $(Get-CurrentLine))
                                    $Name           = $UserToCreate.AccountName
                                    $OU             = $AdminOU
                                    $PassWord       = $UserToCreate.Password
                                    $GroupsToAddTo.Add($AdminUserGroup)
                                    $OnSiteOnly     = $UserToCreate.OnSiteOnly
                                    break
                                } # Admin
                    "Test"      {
                                    Write-Verbose "Creating TST Account"
                                    $Name           = $UserToCreate.AccountName
                                    $OU             = $EnabledUsersOU
                                    $PassWord       = $UserToCreate.Password

                                    if($UserToCreate.WVDOnly)
                                    {
                                        # Do not add to any groups
                                    }
                                    else
                                    {
                                        $GroupsToAddTo.Add($RegularUserGroup)
                                    }
                                    $OnSiteOnly     = $UserToCreate.OnSiteOnly
                                    break
                                } # "test"
                    default     {
                                    Write-Verbose ("{0} Creating Regular Account ({1})" -f $(Get-CurrentLine), $UserToCreate.AccountName)
                                    $Name           = $UserToCreate.AccountName
                                    $OU             = $EnabledUsersOU 
                                    $PassWord       = $UserToCreate.Password

                                    # is the user for WVDOnly Access
                                    if($UserToCreate.WVDOnly)
                                    {
                                        # Do not add user to any additional groups
                                        Write-Verbose ("{0} Account ({1}) is for WVD Only Access" -f $(Get-CurrentLine), $UserToCreate.AccountName)
                                    } # $UserToCreate.WVDOnly
                                    else
                                    {
                                        # Add user to Regular Users group for WVD additional groups
                                        Write-Verbose ("{0} Account ({1}) is NOT for WVD Only Access" -f $(Get-CurrentLine), $UserToCreate.AccountName)

                                        $GroupsToAddTo.Add($RegularUserGroup)
                                    } # else $UserToCreate.WVDOnly

                                    # is the user access for OnSiteOnly access?
                                    $OnSiteOnly     = $UserToCreate.OnSiteOnly
                                    Write-Verbose ("{0} Account ({1}) is for Onsite Only Access ({2})" -f $(Get-CurrentLine), $UserToCreate.AccountName, $OnSiteOnly)

                                    # is the user MDM request?
                                    $MDM            = $UserToCreate.MDM
                                    Write-Verbose ("{0} Account ({1}) is for Mobile Access ({2})" -f $(Get-CurrentLine), $UserToCreate.AccountName, $MDM)                                   

                                    # is the user for TAO?
                                    $TAO            = $UserToCreate.TAO
                                    Write-Verbose ("{0} Account ({1}) is in TAO group ({2})" -f $(Get-CurrentLine), $UserToCreate.AccountName, $TAO)
                                } # default
                } # Switch ($UserToCreate.Type)
                # Change Name to lower then Title Case and reassign to Name (for when Name is all CAPS)
                $Name = (Get-Culture).TextInfo.ToTitleCase($Name.ToLower())

                $NewADUserProperties = [Ordered]@{
                        Name                    = $Name
                        Description             = [String]::Empty
                        SamAccountName          = $Name
                        UserPrincipalName       = "$($Name)@$UPN"
                        DisplayName             = $Name
                        EmployeeID              = $UserToCreate.ID
                        Path                    = $OU
                        Enabled                 = $true
                        AccountPassword         = (ConvertTo-SecureString $Password -AsPlainText -Force)
                        ChangePasswordAtLogon   = $true
                        AccountExpirationDate   = (Get-Date).AddYears(1)
                        Confirm                 = $false
                        ErrorAction             = "Stop"
                    } # $NewADUserProperties
                
                New-ADUser @NewADUserProperties
                
                $ADUser                     = Get-ADUser $Name -Properties whenCreated -ErrorAction Stop
                $UserToCreate.Created       = $true
                $UserToCreate.CreatedDate   = $ADUser.whenCreated

                Write-Verbose ("{0} Create user for OnSiteOnly ({1})" -f $(Get-CurrentLine), $OnSiteOnly)
                if($OnSiteOnly)
                {
                    Write-Verbose ("{0} User is for OnsiteOnly"  -f $(Get-CurrentLine))
                    $ADUser | Set-ADUser -Add @{'msDS-cloudExtensionAttribute2' = 1}
                } # if($OnSiteOnly)
                else
                {
                    Write-Verbose ("{0} User is NOT for OnsiteOnly" -f $(Get-CurrentLine))
                    $ADUser | Set-ADUser -Add @{'msDS-cloudExtensionAttribute2' = 0}
                } # else if($OnSiteOnly)

                if($MDM)
                {
                    Write-Verbose ("{0} User is for MDM"  -f $(Get-CurrentLine))
                    $ADUser | Set-ADUser -Add @{'msDS-cloudExtensionAttribute3' = 1}
                } # if($MDM)
                else
                {
                    Write-Verbose ("{0} User is NOT for MDM"  -f$(Get-CurrentLine))
                    $ADUser | Set-ADUser -Add @{'msDS-cloudExtensionAttribute3' = 0}
                } # else if($MDM)
                
                # If user is in TAO, they are added to TAO Users as well
                if($TAO)
                {
                    Write-Verbose ("{0} User is for TAO"  -f $(Get-CurrentLine))
                    $GroupsToAddTo.Add($TAOGroup)
                } # if TAO user for group
                else
                {
                    Write-Verbose ("{0} User is NOT for TAO" -f $(Get-CurrentLine))
                }

                ForEach($GroupToAddTo in $GroupsToAddTo)
                {
                    Write-Verbose ("Add ({0} to group ({1})" -f $ADUser, $GroupToAddTo )
                    try
                    {
                        $ADGroup = (Get-ADGroup $GroupToAddTo -ErrorAction Stop)
                        Add-ADGroupMember -Identity (Get-ADGroup $GroupToAddTo) -Members $ADUser -ErrorAction Stop
                        $Note = ("{0} added to {1}" -f $ADUser.SamAccountName, $ADGroup.Name )
                        Write-Verbose $Note
                    } #try 
                    catch
                    {
                        $Note = ("Unable to add ({0}) to ({1}) : ({2})" -f $ADUser.SamAccountName, $ADGroup.Name, $Error[0].Exception.Message)
                        Write-Error $Note
                    } # catch
                    finally
                    {
                        $UserToCreate.Notes += $Note
                    } #finally
                } # ForEach($GroupToAddTo in $GroupsToAddTo)

                try
                {
                    # Synchronize AD with AzureAD and get Temporary Access Pass
                    $ScriptBlock = {
                        try
                        {
                            Import-Module ADSync -ErrorAction Stop
                            $ADSyncSyncResults = Start-ADSyncSyncCycle -PolicyType Delta -ErrorAction Stop
                            
                            [PSCustomObject]@{
                                ADSyncSyncResults   = $ADSyncSyncResults
                                Name                = $using:Name
                            }
                        } # try
                        catch
                        {
                            $Error[0]
                        }
                    } # $ScriptBlock

                    $SyncResults = Invoke-Command -ScriptBlock $ScriptBlock -ComputerName $AzureActiveDirectoryVM -ErrorAction Stop -HideComputerName
                    Write-Verbose ("{0} ({1})" -f (Get-CurrentLine), $SyncResults.ADSyncSyncResults)
                } # try Invoke on vm
                catch
                {
                    Write-Warning ($Error[0].Exception.Message)
                }

                # temporary Access Pass
                try
                {
                    Write-Verbose ("{0} Get Temporary Access Pass from Graph API call" -f (Get-CurrentLine))
                    $TemporaryAccessPass = $null 

                    # Create a Temporary Access Pass for a user
                    $BodyParameters = (@{
                        isUsableOnce    = $True
                        startDateTime   = $(Get-Date)
                    }) | ConvertTo-Json

                    $UserId = ("{0}@uce.cia.gov" -f $Name)
                    Connect-MgGraph -TenantId $TenantID -UseDeviceAuthentication -ErrorAction Stop | Out-Null
                    $TemporaryAccessPass = New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $UserId -BodyParameter $BodyParameters -ErrorAction Stop
                    Write-Verbose ("{0} Get Temporary Access Pass as ({1})" -f (Get-CurrentLine), $TemporaryAccessPass)
                }
                catch
                {
                    Write-Warning ("{0} ({1})" -f (Get-CurrentLine), $Error[0].Exception.Message)
                }

                return $UserToCreate
            } # try
            catch
            {
                Write-Error $Error[0]
            } # catch
        } # ShouldProcess
    }# process
} # function New-UCEADUser