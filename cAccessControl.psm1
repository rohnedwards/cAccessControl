
enum Ensure {
	Absent
	Present
}

enum AceType {
	Allow
	Deny
	Audit
}


Add-Type @"
[System.Flags()]
public enum AppliesTo {
	Object = 1,
	ChildContainers = 2,
	ChildObjects = 4,
    DirectChildrenOnly = 8
}
"@

function ConvertPrincipalToSid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string] $Principal
    )

    process {
        Write-Verbose "  Translating principal '$Principal' to SID..."

	    # Is principal already a SID?
	    $SID = $Principal -as [System.Security.Principal.SecurityIdentifier]
	    if ($SID -eq $null) {
		    try {
			    $SID 	= ([System.Security.Principal.NTAccount] $Principal).Translate([System.Security.Principal.SecurityIdentifier])	
		    }
		    catch {
			    Write-Error -Category InvalidArgument ("Unable to convert '{0}' to SecurityIdentifier: {1}" -f $Principal, $_.Exception.Message)
		    }
	    }

        Write-Verbose "    Translated to '$SID'"
	    return $SID
    }
}

function ConvertAceFlagsToAppliesTo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [System.Security.AccessControl.InheritanceFlags] $InheritanceFlags,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [System.Security.AccessControl.PropagationFlags] $PropagationFlags
    )

    process {
        [AppliesTo] $AppliesTo = 0

        Write-Verbose "  Converting InheritanceFlags '$InheritanceFlags' and PropagationFlags '$PropagationFlags' to AppliesTo..."
        if (-not ($PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly)) {
            $AppliesTo = $AppliesTo -bor [AppliesTo]::Object
        }

        if ($PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit) {
            $AppliesTo = $AppliesTo -bor [AppliesTo]::DirectChildrenOnly
        }

        if ($InheritanceFlags -band [System.Security.AccessControl.InheritanceFlags]::ContainerInherit) {
            $AppliesTo = $AppliesTo -bor [AppliesTo]::ChildContainers
        }

        if ($InheritanceFlags -band [System.Security.AccessControl.InheritanceFlags]::ObjectInherit) {
            $AppliesTo = $AppliesTo -bor [AppliesTo]::ChildObjects
        }

        if ($AppliesTo.value__ -eq 0) {
            Write-Error -Category InvalidData "Invalid flags"
        }
        else {
            Write-Verbose "    Converted to '$AppliesTo'"
            $AppliesTo
        }
    }
}

function ConvertAppliesToToAceFlags {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AppliesTo] $AppliesTo
    )

    process {
        [System.Security.AccessControl.InheritanceFlags] $InheritanceFlags = "None"
        [System.Security.AccessControl.PropagationFlags] $PropagationFlags = "None"

        if ($AppliesTo -band [AppliesTo]::ChildContainers) {
            $InheritanceFlags = $InheritanceFlags -bor [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
        }

        if ($AppliesTo -band [AppliesTo]::ChildObjects) {
            $InheritanceFlags = $InheritanceFlags -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        }

        if (-not ($AppliesTo -band [AppliesTo]::Object)) {
            $PropagationFlags = $PropagationFlags -bor [System.Security.AccessControl.PropagationFlags]::InheritOnly
        }

        if ($AppliesTo -band [AppliesTo]::DirectChildrenOnly) {
            $PropagationFlags = $PropagationFlags -bor [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit
        }

        [PSCustomObject] @{
            InheritanceFlags = $InheritanceFlags
            PropagationFlags = $PropagationFlags
        }
    }
}

function GetAces {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Path,
        [Parameter(Mandatory)]
        [string] $AceType,
        [Parameter(Mandatory)]
        [string] $Principal,
        [Parameter(Mandatory)]
        [int] $AccessMask,
        [Parameter(Mandatory)]
        [AppliesTo] $AppliesTo,
        [string] $AuditFlags,
        [switch] $IgnoreInheritedAces,
        [switch] $Specific
    )

    Write-Verbose "  Looking up ACEs that meet the following conditions:"
    $PSBoundParameters.GetEnumerator() | ForEach-Object {
        Write-Verbose ("    {0} = {1}" -f $_.Key, $_.Value)
    }
    $SID = $Principal | ConvertPrincipalToSid -ErrorAction Stop

    $GetAclParams = @{
        Path = $Path
        ErrorAction = "Stop"
    }

    if ($AceType -eq "Audit") {
        $GetAclParams.Audit = $true
        $GetAceMethodName = "GetAuditRules"
    }
    else {
        $GetAceMethodName = "GetAccessRules"
    }

    try {
        $SD = Get-Acl @GetAclParams
    }
    catch {
        Write-Error -Category $_.CategoryInfo ("Error getting security descriptor for '{0}': {1}" -f $Path, $_.Exception.Message)
    }

    $AceFlags = $AppliesTo | ConvertAppliesToToAceFlags

    foreach($CurrentAce in $SD.$GetAceMethodName.Invoke(
        $true,  # Include explicit?
        -not $IgnoreInheritedAces, # Include inherited?
        [System.Security.Principal.SecurityIdentifier]  # Targettype
    )) {
        
        if ($AceType -eq "Audit") { $CurrentAceType = "Audit" }
        else { $CurrentAceType = $CurrentAce.AccessControlType }

        $CurrentAccessMask = $CurrentAce.GetType().InvokeMember("AccessMask", "GetProperty, NonPublic, Instance", $null, $CurrentAce, $null)
        $CurrentAppliesTo = $CurrentAce | ConvertAceFlagsToAppliesTo -Verbose:$false
        Write-Verbose ("    Found ACE: {0} {1} {2} ({3})" -f $CurrentAceType, $CurrentAce.IdentityReference, $AccessMask, $CurrentAppliesTo)

        # Test SID
        if ($CurrentAce.IdentityReference -ne $SID) { 
            Write-Verbose ("      IdentityReference doesn't match (Currently [{0}]; Should be [{1}]" -f $CurrentAce.IdentityReference, $SID)
            continue
        }

        # Test AppliesTo
        if (-not ($CurrentAppliesTo | TestBandOrEquals $AppliesTo -Specific:$Specific)) { 
            Write-Verbose ("      AppliesTo doesn't match (Currently [{0}]; Should be [{0}]" -f $CurrentAppliesTo, $AppliesTo)
            continue 
        }

        # Test AccessMask
        if (-not ($CurrentAccessMask | TestBandOrEquals $AccessMask -Specific:$Specific)) { 
            Write-Verbose "      AccessMask doesn't match (Currently [$CurrentAccessMask]; Should be [$AccessMask])"
            continue 
        }

        # Test AccessControlType/AuditFlags
        if ($AceType -eq "Audit") {
            if (-not ($CurrentAce.AuditFlags | TestBandOrEquals ($AuditFlags -as [System.Security.AccessControl.AuditFlags]) -Specific:$Specific)) { 
                Write-Verbose ("      AuditFlags don't match (Currently [{0}]; Should be [{1}])" -f $CurrentAce.AuditFlags, $AuditFlags)
                continue 
            }
        }
        else {
            if ($CurrentAce.AccessControlType -ne $AceType) { 
                Write-Verbose ("      AccessControlType doesn't match (Currently [{0}]; Should be [{1}])" -f $CurrentAce.AccessControlType, $AceType)
                continue 
            }
        }

        # If it made it here, output the ACE
        Write-Verbose "      ACE passed all tests"
        $CurrentAce
        break
    }
}

function TestBandOrEquals {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [int] $InputObject,
        [Parameter(Mandatory, Position = 0)]
        [int] $TestValue,
        [switch] $Specific
    )

    process {
        if ($InputObject -eq $TestValue) {
            return $true  # This handles situation where 0 and 0 are both input
        }
        elseif (-not $Specific) {
            return [bool] ($InputObject -band $TestValue)
        }
        else {
            return $false
        }
    }
}


[DscResource()]
class cFileAce {

	[DscProperty(Key)]
	[string] $Path

	[DscProperty()]
	[Ensure] $Ensure = "Present"

	[DscProperty(Key)]
	[AceType] $AceType

	[DscProperty(Key)]
	[string] $Principal

	[DscProperty()]
	[string] $FileSystemRights

	[DscProperty(Key)]
	[string] $AppliesTo

	[DscProperty()]
	[string] $AuditFlags

	[DscProperty()]
	[bool] $Specific

	[DscProperty()]
	[bool] $IgnoreInheritedAces

	[void] Set() {
		Write-Verbose "Inside Set()"

        $GetAclParams = @{
            Path = $this.Path
            ErrorAction = "Stop"
        }

        # First, generate ACE:
        # Access and Audit ACEs share the first 4 arguments:
        $AceFlags = $this.AppliesTo | ConvertAppliesToToAceFlags
        $Arguments = @(
            $this.Principal,
            $this.FileSystemRights,
            $AceFlags.InheritanceFlags,
            $AceFlags.PropagationFlags
        )

        # Add the last argument:
        if ($this.AceType -eq "Audit") {
            $GetAclParams.Audit = $true
            $Arguments += $this.AuditFlags
            $AclType = "Audit"
        }
        else {
            $Arguments += $this.AceType
            $AclType = "Access"
        }

        $RuleType = "System.Security.AccessControl.FileSystem${AclType}Rule"
        Write-Verbose ("Creating instance of {0} ({1})" -f $RuleType, ($Arguments -join ", "))
        $Rule = New-Object $RuleType $Arguments

        Write-Verbose ("Calling Get-Acl on '{0}'" -f $this.Path)
        $Acl = Get-Acl @GetAclParams
        if ($this.Specific) {
            if ($this.Ensure -eq "Present") {
                # Add ACE (specific)
                $ModificationMethod = "Set${AclType}Rule"
            }
            else {
                # Remove ACE (specific)
                $ModificationMethod = "Remove${AclType}RuleSpecific"
            }
        }
        else {
            if ($this.Ensure -eq "Present") {
                # Add ACE (not specific)
                $ModificationMethod = "Add${AclType}Rule"
            }
            else {
                # Remove ACE (not specific)
                $ModificationMethod = "Remove${AclType}Rule"
            }
        }

        Write-Verbose "Calling '$ModificationMethod'"
        $Acl.$ModificationMethod.Invoke($Rule)

        # Set-Acl is bad for the file system provider
        (Get-Item $this.Path).SetAccessControl($Acl)
	}
	
	[bool] Test() {
        Write-Verbose ("Test(): Ensure = {0}" -f $this.Ensure)
        
        $GetAcesParams = $this.GetGetAcesParams()
        $MatchingAces = GetAces @GetAcesParams
        
        Write-Verbose ("        Matching ACE count = {0}" -f $MatchingAces.Count)
        $TestResult = [bool] $MatchingAces.Count

        if ($this.Ensure -eq [Ensure]::Absent) { 
            Write-Verbose "        Ensure = Absent; negating current TestResult ($TestResult)"
            $TestResult = -not $TestResult 
        }
        Write-Verbose "        Final TestResult = $TestResult"
        return $TestResult
	}

	[cFileAce] Get() {
		
        $GetAcesParams = $this.GetGetAcesParams()
        $MatchingAce = GetAces @GetAcesParams

        if ($MatchingAce -eq $null) {
            $this.Ensure = [Ensure]::Absent
        }
        elseif ($MatchingAce.Count -eq 1) {
            $this.Ensure = [Ensure]::Present
            $this.FileSystemRights = $MatchingAce.FileSystemRights
            $this.AppliesTo = $MatchingAce | ConvertAceFlagsToAppliesTo -Verbose:$false
            if ($this.AceType -eq "Audit") {
                $this.AuditFlags = $MatchingAce.AuditFlags
            }
        }
        else {
            # How is this handled?
            Write-Error "More than one matchine ACE found!"
        }

        return $this
	}

    [hashtable] GetGetAcesParams() {
        return @{
            Path = $this.Path
            Principal = $this.Principal
            AceType = $this.AceType
            AccessMask = $this.FileSystemRights -as [System.Security.AccessControl.FileSystemRights]
            AppliesTo = $this.AppliesTo
            AuditFlags = $this.AuditFlags
            Specific = $this.Specific
            IgnoreInheritedAces = $this.IgnoreInheritedAces
        }

    }

}

[DscResource()]
class cRegistryAce {

	[DscProperty(Key)]
	[string] $Path

	[DscProperty()]
	[Ensure] $Ensure = "Present"

	[DscProperty(Key)]
	[AceType] $AceType

	[DscProperty(Key)]
	[string] $Principal

	[DscProperty()]
	[string] $RegistryRights

	[DscProperty(Key)]
	[string] $AppliesTo

	[DscProperty()]
	[string] $AuditFlags

	[DscProperty()]
	[bool] $Specific

	[DscProperty()]
	[bool] $IgnoreInheritedAces

	[void] Set() {
		Write-Verbose "Inside Set()"

        $GetAclParams = @{
            Path = $this.Path
            ErrorAction = "Stop"
        }

        # First, generate ACE:
        # Access and Audit ACEs share the first 4 arguments:
        $AceFlags = $this.AppliesTo | ConvertAppliesToToAceFlags
        $Arguments = @(
            $this.Principal,
            $this.RegistryRights,
            $AceFlags.InheritanceFlags,
            $AceFlags.PropagationFlags
        )

        # Add the last argument:
        if ($this.AceType -eq "Audit") {
            $GetAclParams.Audit = $true
            $Arguments += $this.AuditFlags
            $AclType = "Audit"
        }
        else {
            $Arguments += $this.AceType
            $AclType = "Access"
        }

        $RuleType = "System.Security.AccessControl.Registry${AclType}Rule"
        Write-Verbose ("Creating instance of {0} ({1})" -f $RuleType, ($Arguments -join ", "))
        $Rule = New-Object $RuleType $Arguments

        Write-Verbose ("Calling Get-Acl on '{0}'" -f $this.Path)
        $Acl = Get-Acl @GetAclParams
        if ($this.Specific) {
            if ($this.Ensure -eq "Present") {
                # Add ACE (specific)
                $ModificationMethod = "Set${AclType}Rule"
            }
            else {
                # Remove ACE (specific)
                $ModificationMethod = "Remove${AclType}RuleSpecific"
            }
        }
        else {
            if ($this.Ensure -eq "Present") {
                # Add ACE (not specific)
                $ModificationMethod = "Add${AclType}Rule"
            }
            else {
                # Remove ACE (not specific)
                $ModificationMethod = "Remove${AclType}Rule"
            }
        }

        Write-Verbose "Calling '$ModificationMethod'"
        $Acl.$ModificationMethod.Invoke($Rule)

        $Acl | Set-Acl
	}
	
	[bool] Test() {
        Write-Verbose ("Test(): Ensure = {0}" -f $this.Ensure)
        
        $GetAcesParams = $this.GetGetAcesParams()
        $MatchingAces = GetAces @GetAcesParams
        
        Write-Verbose ("        Matching ACE count = {0}" -f $MatchingAces.Count)
        $TestResult = [bool] $MatchingAces.Count

        if ($this.Ensure -eq [Ensure]::Absent) { 
            Write-Verbose "        Ensure = Absent; negating current TestResult ($TestResult)"
            $TestResult = -not $TestResult 
        }
        Write-Verbose "        Final TestResult = $TestResult"
        return $TestResult
	}

	[cRegistryAce] Get() {
		
        $GetAcesParams = $this.GetGetAcesParams()
        $MatchingAce = GetAces @GetAcesParams

        if ($MatchingAce -eq $null) {
            $this.Ensure = [Ensure]::Absent
        }
        elseif ($MatchingAce.Count -eq 1) {
            $this.Ensure = [Ensure]::Present
            $this.RegistryRights = $MatchingAce.RegistryRights
            $this.AppliesTo = $MatchingAce | ConvertAceFlagsToAppliesTo -Verbose:$false
            if ($this.AceType -eq "Audit") {
                $this.AuditFlags = $MatchingAce.AuditFlags
            }
        }
        else {
            # How is this handled?
            Write-Error "More than one matchine ACE found!"
        }

        return $this
	}

    [hashtable] GetGetAcesParams() {
        return @{
            Path = $this.Path
            Principal = $this.Principal
            AceType = $this.AceType
            AccessMask = $this.RegistryRights -as [System.Security.AccessControl.RegistryRights]
            AppliesTo = $this.AppliesTo
            AuditFlags = $this.AuditFlags
            Specific = $this.Specific
            IgnoreInheritedAces = $this.IgnoreInheritedAces
        }

    }

}
