function Get-ADObjectACLs {
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
