# Cheat Sheet | Attack Active-Directory

This cheat sheet contains common enumeration and attack methods for Windows Active Directory with the use of powershell.

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
Get-NetGroup                                          #Information about groups
Get-NetGroup *Admin*                                  #Get all groups that contain the word "admin" in the group name 
```
- **With AD Module:**
```
```
