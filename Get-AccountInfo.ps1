function Get-AccountInfo 
{
    <#
        .SYNOPSIS
            Retrieves account information for a specified user.
        
        .DESCRIPTION
            This function returns the last 5 lines of the account information for a specified user.

        .PARAMETER CurrentInfo
            The current account information for the user.

        .PARAMETER InfoToAdd
            The additional account information to add to the current information.

        .PARAMETER LinesToKeep
            The number of lines to keep from the combined information. The default value is 5.

        .PARAMETER MaxCharacterLength
            The maximum character length for the combined information. The default value is 1024.

        .EXAMPLE

            Get-AccountInfo -CurrentInfo $currentInfo -InfoToAdd $infoToAdd -verbose

            This example retrieves the last 5 lines of the account information for a specified user.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [string]$CurrentInfo
        ,
        [Parameter()]
        [string]$InfoToAdd
        ,
        [Parameter()]
        [int]$LinesToKeep = 5
        ,
        [Parameter()]
        [int]$MaxCharacterLength = 1024
    ) # param
    process
    {
        $FunctionName = $MyInvocation.MyCommand.Name
        Write-Verbose ("{0} `t`tEntering {1}" -f [DateTime]::Now, $FunctionName)
        # Split the strings into separate lines
        
        $CurrentLines = $CurrentInfo -split "`n"
        Write-Verbose ("{0} `t`t`tCurrent Lines: {1}" -f [DateTime]::Now, $CurrentLines.Count)
 
        Write-Verbose ("{0} `t`t`tInfo To Add : {1}" -f [DateTime]::Now, $InfoToAdd)
    
        # Combine the lines from CurrentInfo and InfoToAdd
        $CombinedLines = $InfoToAddLines + $currentLines
    
        # Get the last five lines or less
        $UpdatedLines = $CombinedLines[-$LinesToKeep..-1]
    
        # Join the lines into a single string
        $UpdatedInfo = $UpdatedLines -join "`n"
    
        # Check if the updated info exceeds the maximum character length
        if ($updatedInfo.Length -gt $MaxCharacterLength) {
            $updatedInfo = $updatedInfo.Substring(0, $MaxCharacterLength)
        }
    
        Write-Verbose ("{0} `t`tLeaving {1}" -f [DateTime]::Now, $FunctionName)
        # Output the updated account information
        return $updatedInfo
    } # process
} # End of Get-AccountInfo function

$ContentToAdd = $null
$InfoToAdd = ("{0:MM-dd-yyyy HH:mm:ss.fff}" -f [DateTime]::Now)
$ContentToAdd = Get-AccountInfo -CurrentInfo $ContentToAdd -InfoToAdd $InfoToAdd -verbose
$ContentToAdd