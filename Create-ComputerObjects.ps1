Import-Module ActiveDirectory

#List of computernames to create
$Comps = @()
$Comps += @"
MUHJW-4421DQ
MUHJW-4421GB
MUHJW-4421H9
MUHJW-4421FH
MUHJW-4421FY
MUHJW-4421F0
MUHJW-4421GT
"@.split("`n") | foreach {$_.trim()}

#######################################################################################################
#This block can be used for testing to make sure the objects don't exist.  
#Don't comment-in the remove-adcomputer unless youre sure you want a clean slate for all these objects.
#$comps | foreach {
    #try {Remove-ADComputer $_ -Confirm:$false -EA STOP}
    #catch {}
    #Get-ADComputer $_
#    }
#Wait buffer for remove
#Start-Sleep -Seconds 5
#######################################################################################################

#The groups that the computer accounts needs to be a member of
#Can be empty
$Groups = @()
$Groups += @"
"@.split("`n") | foreach {$_.trim()}

#Description field for these objects; leave as "" if no descritption requested
$Description = ""

#Distinguished Name (DN) of the OU to place these objects
$OUPath = "OU=NOSC Computers,OU=NOSC,OU=Bases,DC=acc,DC=accroot,DC=ds,DC=af,DC=smil,DC=mil"

#The group(s) to grant join rights for these computers
#Can be empty, but then theres no point in using this script vs just new-adcompuer
$ToJoinGroups = @()
$ToJoinGroups += @"
83 NOS Workstation Admins
"@.split("`n") | foreach {$_.trim()}

#################################################################
#Do not edit beyond this point unless you know what you're doing.
#################################################################

#Make sure OU exists
try {Get-ADOrganizationalUnit $OUPath -EA Stop | Out-Null}
catch {
    Write-host "Error: `"$OUPath`" not found.  Script aborting."
    Read-Host -Prompt "Press enter to exit script."
    exit
}

#Make sure join group/user exists
foreach ($ToJoin in $ToJoinGroups) {
    try {
        (Get-ADUser $ToJoin -ErrorAction Stop).SamAccountName
        }
    catch {
        try {
            $ToJoin =  (Get-ADGroup -Filter {(cn -eq $ToJoin) -or (Name -eq $ToJoin) -or (SamAccountName -eq $ToJoin)} -ErrorAction Stop).SamAccountName
            if (!$ToJoin) {throw [System.IO.FileNotFoundException] "This is just to hit the catch loop"}
            }
        catch {
            Write-host "Error: User/Group `"$ToJoin`" not found.  Script aborting."
            Read-Host -Prompt "Press enter to exit script."
            exit
            }
        }
    }

#Make Computer objects
Write-Host -ForegroundColor Green "Making Computers"
foreach ($computerName in $Comps) {
    New-ADComputer -Name $computerName -SAMAccountName ($computerName + "$") -Path $OUPath -Description $Description -OtherAttributes @{'userAccountControl'=4128} -EA SilentlyContinue
    }

#We need a pause after creation
while (!(Get-ADComputer $Comps[($Comps.count - 1)])) {}
Start-Sleep -Seconds 5

#Bad Implementation, possible member limit?
#Get newly created SAMAccountName
#$compSams = @()
#foreach ($comp in $Comps) {
    #$compSams += (Get-ADComputer $comp).SAMAccountName
    #}

#Add computers to groups
if ($Groups[0] -ne "") {
    Write-Host -ForegroundColor Green "Adding Computers to groups"
    foreach ($group in $Groups) {
        foreach ($comp in $Comps) {
            try {Add-ADGroupMember -Identity $group -Members (Get-ADComputer $comp | select -ExpandProperty distinguishedname) -EA Stop}
            catch {Write-Host $group : $comp : $_}
            }
        }
    }

#Another pause just in case
while ($Groups -and !(Get-ADComputer $Comps[($Comps.count - 1)] -Properties memberof).memberof.contains((Get-ADGroup $Groups[($Groups.count - 1)]).distinguishedName)) {}
Start-Sleep -Seconds 5
    
#Set join rights
#The minimum rights needed are reset password, write account restrictions, validate write to dnshostname, and validated write to service principal name.
#These are the rights granted when creating the object via aduc.
Write-Host -ForegroundColor Green "Setting Join Rights"
foreach ($computerName in $Comps) {    
    try {
        Remove-Variable comp -EA SilentlyContinue
        $comp = get-adcomputer -Filter {name -eq $computerName} | select -ExpandProperty DistinguishedName
        if ($comp -eq $null) {throw "No computer found"}
        $computerACL = "AD:\" + $comp | Get-Acl -ErrorAction Stop
        }
    catch {
        Write-host "Error: Computer Name" $computerName "not found"
        pause
        continue
        }
    
    foreach ($ToJoin in $ToJoinGroups) {
        $IdentityReference = [System.Security.Principal.NTAccount]$ToJoin
        #Read Public Information
        $computerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
            $IdentityReference,
            "ReadProperty",  # Validated Write access mask ([System.DirectoryServices.ActiveDirectoryRights])
            "Allow", # ACE type ([System.Security.AccessControl.AccessControlType])
            "E48D0154-BCF8-11D1-8702-00C04FB96050",  # GUID for Public Information
            "None",  # ACE will only apply to the object it's assigned to ([System.DirectoryServices.ActiveDirectorySecurityInheritance])
            [guid]::Empty                            # Inherited object type (in this case in can apply to any objects)
            )))

        #Read Personal Information
        $computerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
            $IdentityReference,
            "ReadProperty",  # Validated Write access mask ([System.DirectoryServices.ActiveDirectoryRights])
            "Allow", # ACE type ([System.Security.AccessControl.AccessControlType])
            "77B5B886-944A-11D1-AEBD-0000F80367C1",  # GUID for Personal Information
            "None",  # ACE will only apply to the object it's assigned to ([System.DirectoryServices.ActiveDirectorySecurityInheritance])
            [guid]::Empty                            # Inherited object type (in this case in can apply to any objects)
            )))

        #Read MS-TS-GatewayAccess
        $computerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
            $IdentityReference,
            "ReadProperty",  # Validated Write access mask ([System.DirectoryServices.ActiveDirectoryRights])
            "Allow", # ACE type ([System.Security.AccessControl.AccessControlType])
            "FFA6F046-CA4B-4FEB-B40D-04DFEE722543",  # GUID for MS-TS-GatewayAccess
            "None",  # ACE will only apply to the object it's assigned to ([System.DirectoryServices.ActiveDirectorySecurityInheritance])
            [guid]::Empty                            # Inherited object type (in this case in can apply to any objects)
            )))

        #Read DNS Host Name Attributes
        $computerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
            $IdentityReference,
            "ReadProperty",  # Validated Write access mask ([System.DirectoryServices.ActiveDirectoryRights])
            "Allow", # ACE type ([System.Security.AccessControl.AccessControlType])
            "72E39547-7B18-11D1-ADEF-00C04FD8D5CD",  # GUID for DNS Host Name Attributes
            "None",  # ACE will only apply to the object it's assigned to ([System.DirectoryServices.ActiveDirectorySecurityInheritance])
            [guid]::Empty                            # Inherited object type (in this case in can apply to any objects)
            )))

        #Read & Write Account Restrictions
        $computerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
            $IdentityReference,
            "WriteProperty, ReadProperty",  # Access mask
            "Allow",
            "4c164200-20c0-11d0-a768-00aa006e0529",  # GUID for 'Account Restrictions' PropertySet
            "None",
            [guid]::Empty
            )))

        # Validated write to service principal name
        $computerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
            $IdentityReference,
            "Self",  # Access mask
            "Allow",
            "f3a64788-5306-11d1-a9c5-0000f80367c1",  # GUID for 'Validated write to service principal name'
            "None",
            [guid]::Empty
            )))

        # Validated write to DNS host name
        $computerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
            $IdentityReference,
            "Self",  # Validated Write access mask ([System.DirectoryServices.ActiveDirectoryRights])
            "Allow", # ACE type ([System.Security.AccessControl.AccessControlType])
            "72e39547-7b18-11d1-adef-00c04fd8d5cd",  # GUID for 'Validated write to DNS host name'
            "None",  # ACE will only apply to the object it's assigned to ([System.DirectoryServices.ActiveDirectorySecurityInheritance])
            [guid]::Empty                            # Inherited object type (in this case in can apply to any objects)
            )))

        #DeleteTree, ExtendedRight, Delete, GenericRead
        $computerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
            $IdentityReference,
            "DeleteTree, ExtendedRight, Delete, GenericRead",  # Validated Write access mask ([System.DirectoryServices.ActiveDirectoryRights])
            "Allow", # ACE type ([System.Security.AccessControl.AccessControlType])
            "00000000-0000-0000-0000-000000000000",  # GUID for DeleteTree, ExtendedRight, Delete, GenericRead
            "None",  # ACE will only apply to the object it's assigned to ([System.DirectoryServices.ActiveDirectorySecurityInheritance])
            [guid]::Empty                            # Inherited object type (in this case in can apply to any objects)
            )))

        # Reset password
        $computerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
            $IdentityReference,
            "ExtendedRight",  # Access mask
            "Allow", 
            "00299570-246d-11d0-a768-00aa006e0529",  # GUID for 'Reset Password' extended right
            "None",
            [guid]::Empty
            )))

        #Write Computer Name (pre-Windows 2000)
        $computerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
            $IdentityReference,
            "WriteProperty",  # Validated Write access mask ([System.DirectoryServices.ActiveDirectoryRights])
            "Allow", # ACE type ([System.Security.AccessControl.AccessControlType])
            "3e0abfd0-126a-11d0-a060-00aa006c33ed",  # GUID for "Write Computer Name (pre-Windows 2000)"
            "None",  # ACE will only apply to the object it's assigned to ([System.DirectoryServices.ActiveDirectorySecurityInheritance])
            [guid]::Empty                            # Inherited object type (in this case in can apply to any objects)
            )))

        #Write Display-Name
        $computerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
            $IdentityReference,
            "WriteProperty",  # Validated Write access mask ([System.DirectoryServices.ActiveDirectoryRights])
            "Allow", # ACE type ([System.Security.AccessControl.AccessControlType])
            "bf967953-0de6-11d0-a285-00aa003049e2",  # GUID for Display-Name
            "None",  # ACE will only apply to the object it's assigned to ([System.DirectoryServices.ActiveDirectorySecurityInheritance])
            [guid]::Empty                            # Inherited object type (in this case in can apply to any objects)
            )))

        #Write Description
        $computerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
            $IdentityReference,
            "WriteProperty",  # Validated Write access mask ([System.DirectoryServices.ActiveDirectoryRights])
            "Allow", # ACE type ([System.Security.AccessControl.AccessControlType])
            "bf967950-0de6-11d0-a285-00aa003049e2",  # GUID for Description
            "None",  # ACE will only apply to the object it's assigned to ([System.DirectoryServices.ActiveDirectorySecurityInheritance])
            [guid]::Empty                            # Inherited object type (in this case in can apply to any objects)
            )))

        #Write Logon Information
        $computerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
            $IdentityReference,
            "WriteProperty",  # Validated Write access mask ([System.DirectoryServices.ActiveDirectoryRights])
            "Allow", # ACE type ([System.Security.AccessControl.AccessControlType])
            "5f202010-79a5-11d0-9020-00c04fc2d4cf",  # GUID for Logon Information
            "None",  # ACE will only apply to the object it's assigned to ([System.DirectoryServices.ActiveDirectorySecurityInheritance])
            [guid]::Empty                            # Inherited object type (in this case in can apply to any objects)
            )))
        }
    $computerACL | Set-Acl

    #This resets the computer object, clearing its password
    #dsmod computer $comp -reset 2>$null
    }
