![Title](images/text02.png 'Text')

This cheat sheet contains common enumeration and attack methods for Windows Active Directory with the use of powershell.

Updating....

## Using PowerView:
```
. .\PowerView.ps1
```
Link: ![PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
## Using AD Module
```
Import-Module .\Microsoft.ActiveDirectory.Management.dll
Import-Module .\ActiveDirectory\ActiveDirectory.psd1
```
Link: ![AD Module](https://github.com/samratashok/ADModule)

## Enumeration:

### Enumeration Users:

- **With PowerView:**
```
Get-NetUser                                           #Get the list of users
Get-NetUser -Username user01                          #Enumeration on user "user01"
Get-NetUser | select cn                               #Get the list of users from cn common-name
Get-NetUser | select name                             #Get the list of users from name
Get-UserProperty                                      #Lists all properties
Get-UserProperty –Properties pwdlastset               #Displays when the password was set
Get-UserProperty -Properties whencreated              #Displays when the accounts were created
```
- **With AD Module:**
```
Get-ADUser -Filter *                                                                                      #Get the list of users
Get-ADUser -Filter * -Properties *                                                                        #Get the list of users with properties
Get-ADUser -Filter * -Properties * | select Samaccountname,Description                                    #List samaccountname and description for users
Get-ADUser -Filter * -Properties * | select cn                                                            #Get the list of users from cn common-name
Get-ADUser -Filter * -Properties * | select name                                                          #Get the list of users from name
Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}  #Displays when the password was set
```

### Enumeration Computers:

- **With PowerView:**
```
Get-NetComputer                                       #Get the list of computers in the current domain
Get-NetComputer -FullData                             #Get the list of computers in the current domain with complete data 
Get-NetComputer -FullData | select operatingsystem    #Get the list of computers with their operating system
Get-NetComputer -FullData | select name               #Get the list of computers with their name
Get-NetComputer -Ping                                 #Send a ping to check if the computers are working
```
- **With AD Module:**
```
Get-ADComputer -Filter * -Properties *                                               #Get the list of computers in the current domain with complete data 
Get-ADComputer -Filter * -Properties OperatingSystem | select name,OperatingSystem   #Get the list of computers with their operating system
Get-ADComputer -Filter * | select Name                                               #Get the list of computers with their name
```

### Enumeration Groups and Members:

- **With PowerView:**
```
Get-NetGroup                                                               #Information about groups
Get-NetGroup *Admin*                                                       #Get all groups that contain the word "admin" in the group name 
Get-NetGroupMember -GroupName "Domain Admins" -Recurse                     #Get all members of the "Domain Admins" group
Get-NetGroupMember -GroupName "Enterprise Admins" –Domain domainxxx.local  #Query the root domain as the "Enterprise Admins" group exists only in the root of a forest
Get-NetGroup -UserName "user01"                                            #Get group membership for "user01"
```
- **With AD Module:**
```
Get-ADGroup -Filter 'Name -like "*admin*"' | select Name                   #Get all groups that contain the word "admin" in the group name
Get-ADGroupMember -Identity "Domain Admins" -Recursive                     #Get all members of the "Domain Admins" group
Get-ADPrincipalGroupMembership -Identity user01                            #Get group membership for "user01"
```

### Enumeration Shares:

- **With PowerView:**
```
Invoke-ShareFinder -Verbose                                             #Find shares on hosts in the current domain                   
Invoke-FileFinder -Verbose                                              #Find sensitive files on computers in the current domain
Get-NetFileServer                                                       #Search file servers. Lot of users use to be logged in this kind of server
Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC –Verbose  #Find shares excluding standard, print and ipc.
```

### Enumeration OUI and GPO:

- **With PowerView:**
```
Get-NetOU                                                                   #Get the organizational units in a domain
Get-NetOU -FullData                                                         #Get the organizational units in a domain with full data 
Get-NetOU "ouiexample" | %{Get-NetComputer -ADSpath $_}                     #Get all computers from "ouiexample". Ouiexample --> organizational Units
Get-NetGPO                                                                  #Retrieve the list of GPOs present in the current domain
Get-NetGPO -ADSpath 'LDAP://cn={example},CN=example'                        #Enumerate GPO applied on the example OU
```
- **With AD Module:**
```
Get-ADOrganizationalUnit -Filter * -Properties *                            #Get the organizational units in a domain
```

### Enumeration ACL:

- **With PowerView:**
```
Get-ObjectAcl -SamAccountName "users" -ResolveGUIDs                         #Enumerates the ACLs for the users group
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs                 #Enumerates the ACLs for the Domain Admins group
Get-ObjectAcl -ADSprefix 'CN=Administrator,CN=Users' -Verbose               #Get the acl associated with a specific prefix
Invoke-ACLScanner -ResolveGUIDs                                             #Find interesting ACLs
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "user"}     #check for modify rights/permissions for the user group
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "RDPusers"} #check for modify rights/permissions for the RDPUsers group
```

### Domain Trust mapping:

- **With PowerView:**
```
Get-NetDomainTrust                                                          #Get the list of all trusts within the current domain
Get-NetDomainTrust -Domain us.domain.corporation.local                      #Get the list of all trusts within the indicated domain
```
**Example**
![Main Logo](images/Example_trust01.PNG 'Example01')

- **With AD Module:**
```
Get-ADTrust -Filter *                                                       #Get the list of all trusts within the current domain
Get-ADTrust -Identity us.domain.corporation.local                           #Get the list of all trusts within the indicated domain
```
