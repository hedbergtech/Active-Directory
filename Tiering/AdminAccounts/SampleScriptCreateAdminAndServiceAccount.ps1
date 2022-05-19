# Version 1.0
# Author:mikal.nystrom@truesec.com

# Import this module before running any of the commands later in this file
Import-Module <PATH>:\TSxUtilityModule.psm1 -Force -Verbose


# -ShortName admbobu: when the user is created it will add T0, T1, T2 or TE as a prefix for the account, so Bob Builder will be admbobu in the commandline, 
# but the account will be named admbobut0 when created, like "admbobu"
# - FirstName is the name of the user, like "Bob"
# - Last name is the surname, like "Builder"
#  -Description is the Description, like "Bob Builder"
#  -AccountType is the tier, like T0 for tier 0
#  -AddToSilo $true will add the user account to the correct tier when creating the account
# In general, the shortname in the command will be the same for a user that needs all 4 tiers on the command, like you see in the sample below.

# Add T0 Account, use -AddToSilo $true to add the user to the T0 silo    
New-TSxAdminAccount -ShortName admpuny -FirstName Putte -LastName Nystrom -Description "Putte Nystrom" -AccountType T0 -AddToSilo $true

# Add T1 Account, -AddToSilo $false means that the user will not be added to a Silo.
New-TSxAdminAccount -ShortName admpuny -FirstName Putte -LastName Nystrom -Description "Putte Nystrom" -AccountType T1 -AddToSilo $false

# Add T2 Account, (not implemented in this environment right now)
New-TSxAdminAccount -ShortName admpuny -FirstName Putte -LastName Nystrom -Description "Putte Nystrom" -AccountType T2 -AddToSilo $false

# Add T1 or T2 account with limited access
New-TSxAdminAccount -ShortName admpunylimited -FirstName Putte -LastName Nystrom -Description "Putte Nystrom [EXT]" -AccountType T1 -AddToSilo $false -Limited
New-TSxAdminAccount -ShortName admpunylimited -FirstName Putte -LastName Nystrom -Description "Putte Nystrom [EXT]" -AccountType T2 -AddToSilo $false -Limited

# Add TierEndpoint and Connection accounts (Not implemented in this environment right now)
New-TSxAdminAccount -ShortName admpuny -FirstName Putte -LastName Nystrom -Description "Putte Nystrom [EXT]" -AccountType TE
New-TSxAdminAccount -ShortName admpuny -FirstName Putte -LastName Nystrom -Description "Putte Nystrom [EXT]" -AccountType Con

$items = Import-Csv -Path .\Users.txt


foreach ($item in $items){
    New-TSxAdminAccount -ShortName $item.shortname -FirstName $item.FirstName -LastName $item.LastName -Description $item.Description -AccountType T0 -AddToSilo $false
}  

foreach ($item in $items){
    New-TSxAdminAccount -ShortName $item.shortname -FirstName $item.FirstName -LastName $item.LastName -Description $item.Description -AccountType T1 -AddToSilo $false
}  

foreach ($item in $items){
    New-TSxAdminAccount -ShortName $item.shortname -FirstName $item.FirstName -LastName $item.LastName -Description $item.Description -AccountType T2 -AddToSilo $false
}  

foreach ($item in $items){
    New-TSxAdminAccount -ShortName $item.shortname -FirstName $item.FirstName -LastName $item.LastName -Description $item.Description -AccountType TE
}  

foreach ($item in $items){
    New-TSxAdminAccount -ShortName $item.shortname -FirstName $item.FirstName -LastName $item.LastName -Description $item.Description -AccountType Con
}  

# Create new OUs in Admin Tier
# Variables
$TierOUName = "Admin"
$CompanyName = "Customer"

# Create OU in Tier T0 
New-TSxSubOU -Tier T0 -Name "ExampleServers" -Description "Example OU" -TierOUName $TierOUName -CompanyName $CompanyName

# Create OU in Tier T1 
New-TSxSubOU -Tier T1 -Name "ExampleServers" -Description "Example OU" -TierOUName $TierOUName -CompanyName $CompanyName

# Create OU in Tier TE 
New-TSxSubOU -Tier TE -Name "ExampleServers" -Description "Example OU" -TierOUName $TierOUName -CompanyName $CompanyName

# After New-TSxSubOU is done you need to update the GPO to add the new created AD Admin group. 