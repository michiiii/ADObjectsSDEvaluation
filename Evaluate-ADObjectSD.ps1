<#
.SYNOPSIS
Retrieve access control lists for an Active Directory object based on a search string.

.DESCRIPTION
This function fetches the ACLs for an AD object which matches the given search string. It returns the ACLs in a sorted and unique manner.

.PARAMETER SearchString
The search string used to identify the AD object.

.EXAMPLE
Get-ADObjectAccessControlList -SearchString "Admin"

.NOTES
File Name      : xxxx.ps1
Author         : Your Name
Prerequisite   : PowerShell V2
Copyright 2023 : Your Organization
#>
function Get-ADObjectACL {
    param (
        [Parameter(Mandatory=$true)]
        [string]$SearchString
    )

    Import-Module ActiveDirectory

    # Construct a filter based on the search string
    $filter = "Name -like '*$SearchString*'"

    # Get the AD object using the constructed filter
    $object = Get-ADObject -Filter $filter -Properties DistinguishedName
    if (-not $object) {
        Write-Error "Object not found!"
        return $null
    }

    $acl = Get-Acl -Path "AD:\$($object.DistinguishedName)"
    
    $results = @()

    foreach ($ace in $acl.Access) {
        # Splitting the rights if there are multiple rights combined
        $rights = $ace.ActiveDirectoryRights -split ', '

        foreach ($right in $rights) {
            $results += [PSCustomObject]@{
                DistinguishedName     = $object.DistinguishedName   # Add the DN to the output
                IdentityReference     = $ace.IdentityReference
                ActiveDirectoryRight  = $right
                AccessControlType     = $ace.AccessControlType
                ObjectType            = $ace.ObjectType
                InheritanceType       = $ace.InheritanceType
                InheritedObjectType   = $ace.InheritedObjectType
            }
        }
    }

    # Remove duplicate entries
    $uniqueResults = $results | Group-Object DistinguishedName, IdentityReference, ActiveDirectoryRight, AccessControlType | ForEach-Object { $_.Group | Select-Object -First 1 }

    # Sort the results by IdentityReference
    $sortedResults = $uniqueResults | Sort-Object IdentityReference

    # Return the sorted, unique ACEs as an array of objects
    return $sortedResults
}


<#
.SYNOPSIS
Retrieve the owner of an Active Directory object based on a search string.

.DESCRIPTION
This function fetches the owner of an AD object which matches the given search string.

.PARAMETER SearchString
The search string used to identify the AD object.

.EXAMPLE
Get-ADObjectOwnership -SearchString "Admin"

#>
function Get-ADObjectOwnership {
    param (
        [Parameter(Mandatory=$true)]
        [string]$SearchString
    )

    Import-Module ActiveDirectory

    # Construct a filter based on the search string
    $filter = "Name -like '*$SearchString*'"

    # Get the AD object using the constructed filter
    $object = Get-ADObject -Filter $filter -Properties DistinguishedName
    if (-not $object) {
        Write-Error "Object not found!"
        return $null
    }

    $acl = Get-Acl -Path "AD:\$($object.DistinguishedName)"
    $owner = $acl.Owner

    return $owner
}
