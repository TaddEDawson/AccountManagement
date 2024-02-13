#Requires -Module ActiveDirectory
<#
    .SYNOPSIS

    .PARAMETER SamAccountName

    .PARAMETER Test

    .PARAMETER New

    .PARAMETER Unlock

    .PARAMETER Reset

    .PARAMETER Enable

    .PARAMETER Extend

    .PARAMETER Disable

#>
[CmdletBinding(
    DefaultParameterSetName = "TEST",
    SupportsShouldProcess
)]
param
(
    [Parameter(ValueFromPipeline)]
    [Parameter(ParameterSetName = "TEST")]
    [Parameter(ParameterSetName = "NEW")]
    [Parameter(ParameterSetName = "UNLOCK")]
    [Parameter(ParameterSetName = "RESET")]
    [Parameter(ParameterSetName = "ENABLE")]
    [Parameter(ParameterSetName = "EXTEND")]
    [Parameter(ParameterSetName = "DISABLE")]
    $SamAccountName
    ,
    [Parameter(ParameterSetName = "TEST")]
    [Switch] $Test
    ,
    [Parameter(ParameterSetName = "NEW")]
    [Switch] $New
    , 
    [Parameter(ParameterSetName = "UNLOCK")]
    [Switch] $Unlock
    ,
    [Parameter(ParameterSetName = "RESET")]
    [Switch] $Reset
    ,
    [Parameter(ParameterSetName = "ENABLE")]
    [Switch] $Enable
    ,
    [Parameter(ParameterSetName = "EXTEND")]
    [Switch] $Extend
    ,
    [Parameter(ParameterSetName = "DISABLE")]
    [Switch] $Disable
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

    function Extend-User
    {
        [CmdletBinding()]
        param ($SamAccountName)
        process
        {
            $FunctionName = "Extend-User"
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

        $processObject.TypeOfUser = (
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

        $processObject.ADUser = (
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
                Extend-User -SamAccountname $processObject.SamAccountName
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
        Write-Verbose ("{0} `t Processed ({1}) for ({2} in ({3}) seconds" -f [DateTime::Now], $processObject.SamAccountName, $processObject.ActionToTake, $processObject.Duration)
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
