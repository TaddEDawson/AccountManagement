# AccountManagement

Generics for Account Management

## Actions

1. TEST
1. NEW
1. UNLOCK
1. RESET
1. ENABLE
1. EXTEND
1. DISABLE

## Parameters with Default values

1. SamAccountName
    1. No default
    1. Accepts via Pipeline or Name
1. Switches
    1. TEST
        1. Default if no switch selected
    1. NEW
    1. UNLOCK
    1. RESET
    1. ENABLE
    1. EXTEND
    1. DISABLE
1. EnabledUsersOU
    1. "OU=Enabled Users,OU=User Accounts,DC=theuce,DC=onmicrosoft,DC=com"
1. EnabledAdminOU
    1. "OU=Accounts,OU=Admin,DC=theuce,DC=onmicrosoft,DC=com"
1. EnabledNSEOU
    1. "OU=Service Accounts,OU=Admin,DC=theuce,DC=onmicrosoft,DC=com"
1. DisabledUsersOU
    1. "OU=Disabled Users,OU=User Accounts,DC=theuce,DC=onmicrosoft,DC=com"
1. DisabledAdminsOU
    1. "OU=Disabled,OU=Admin,DC=theuce,DC=onmicrosoft,DC=com"
1. DisabledNSEOU
    1. "OU=Disabled,OU=Admin,DC=theuce,DC=onmicrosoft,DC=com"
1. UPN
    1. "uce.avc.gov"
1. RegularUserGroup
    1. "UCE Users"
1. Common
    1. Verbose
    1. WhatIf
    1. Confirm

## Outline of script request

1. Unlock-uce-std-acct.ps1
    1. Checks if a std account is locked > If yes, unlocks acct
1. unlock-uce-acct.ps1
    1. Checks if the account is locked > If yes, unlocks acct
1. reset-uce-std-acct-password.ps1
    1. Reset std acct password > provides new password
    1. Runs unlock-uce-std-acct.ps1
1. reset-uce-acct-password.ps1
    1. Reset acct password > provides new password
    1. Runs unlock-uce-acct.ps1
1. new-uce-std-user.ps1 : (based on New-UCEUser-v2.ps1)
    1. Only create standard accts
1. new-uce-user.ps1 : (based on New-UCEUser-v2.ps1)
    1. Create any UCE acct
1. extend-uce-std-user.ps1 - Currently done manually in Active Directory
    1. Extends a standard acct
1. extend-uce-user.ps1 - Currently done manually in Active Directory
    1. Extends any UCE acct
1. disable-uce-std-user.ps1 - Currently done manually in Active Directory
    1. Disables a standard acct > Move acct to Disabled Users OU within User Accounts OU
1. disable-uce-user.ps1 - Currently done manually in Active Directory
    1. disables any UCE acct > Then does the following:
        1. Standard Accts move to Disabled Users OU within User Accounts OU
        1. Privileged Accts move to Disabled OU within the Admin OU
        1. Service Accts stay in Service Accounts OU in Admin OU (**Verify where should disabled service accounts go)

## Additional Items

1. Is TAOGroup a requirement for the script?
1. Is OnSiteOnly 'msDS-cloudExtensionAttribute2' a requirement for the script?
1. Is AccountExpirationDate still 1 year from Creation or Enable?
    1. example (Get-Date).AddYears(1)
1. What notes are to be appended to the Telephones Note?
1. Is DeliverToMailboxAndForward a requirement for the script?
    1. For example
        1. Set-Mailbox "<daniel@uce.avc.gov>" -DeliverToMailboxAndForward $true -ForwardingSmtpAddress "<daniel@move.uce.avc.gov>"
1. Determine how to limit the access to selected scripts by the various groups.
    1. Group Membership is captured at run time for the user running the script.
    1. Which Group or Groups for each action should be permitted?
    1. Role Based Groups for actions?
