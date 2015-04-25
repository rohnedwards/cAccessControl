
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
        [System.Security.AccessControl.AuditFlags] $AuditFlags,
        [switch] $IgnoreInheritedAces,
        [switch] $Specific
    )

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
    $SD.$GetAceMethodName.Invoke(
        $true,  # Include explicit?
        -not $IgnoreInheritedAces, # Include inherited?
        [System.Security.Principal.SecurityIdentifier]  # Targettype
    ) | ForEach-Object {
        
        # Test SID
        if ($_.IdentityReference -ne $SID) { return }

        # Test AppliesTo
        if (-not ($_ | ConvertAceFlagsToAppliesTo | TestBandOrEquals $AppliesTo -Specific:$Specific)) { return }

        # Test AccessMask
        $CurrentAccessMask = $_.GetType().InvokeMember("AccessMask", "GetProperty, NonPublic, Instance", $null, $_, $null)
        if (-not ($CurrentAccessMask | TestBandOrEquals $AccessMask -Specific:$Specific)) { return }

        # Test AccessControlType/AuditFlags
        if ($AceType -eq "Audit") {
            if (-not ($_.AuditFlags | TestBandOrEquals $AuditFlags -Specific:$Specific)) { return }
        }
        else {
            if ($_.AccessControlType -ne $AceType) { return }
        }

        # If it made it here, output the ACE
        $_
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
	[System.Security.AccessControl.FileSystemRights] $FileSystemRights

	[DscProperty(Key)]
	[string] $AppliesTo

	[DscProperty()]
	[System.Security.AccessControl.AuditFlags] $AuditFlags

	[DscProperty()]
	[bool] $Specific

	[DscProperty()]
	[bool] $IgnoreInheritedAces

	[void] Set() {
		Write-Verbose "Inside Set()"
	}
	
	[bool] Test() {
		return [bool] ($this.Get().Where({ $_.Ensure -eq $this.Ensure }))
	}

	[cFileAce] Get() {
		
        $GetAcesParams = @{
            Path = $this.Path
            Principal = $this.Principal
            AceType = $this.AceType
            AccessMask = $this.FileSystemRights.value__
            AppliesTo = $this.AppliesTo
            AuditFlags = $this.AuditFlags
            Specific = $this.Specific
            IgnoreInheritedAces = $this.IgnoreInheritedAces
        }
        $MatchingAce = GetAces @GetAcesParams

        if ($MatchingAce -eq $null) {
            $this.Ensure = [Ensure]::Absent
        }
        elseif ($MatchingAce.Count -eq 1) {
            $this.Ensure = [Ensure]::Present
            $this.AccessMask = $MatchingAce.AccessMask
            $this.AppliesTo = $MatchingAce.AppliesTo
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

}