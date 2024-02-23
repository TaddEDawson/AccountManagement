function Test
{
    # Define a custom object with properties
    $customObject = [PSCustomObject]@{
        Name = "John Doe"
        Date = Get-Date
        OU1 = "OU1"
        OU2 = "OU2"
        OU3 = "OU3"
    } # End of custom object
    Update-TypeData -TypeName PSObject -DefaultDisplayPropertySet Name, Date, OU1 -Force
    return $customObject
} # End of function Test

Test

Test | Format-List * -Force
