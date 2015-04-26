configuration TestRegistryAceResource {
    Import-DscResource -Module cAccessControl

    $RegistryPath = "HKLM:\SOFTWARE\ps_dsc_test"
    Registry DscTestKey {
        Key = $RegistryPath
        ValueName = ""
    }

    cRegistryAce DscTestKeyAccessAce1 {
        Path = $RegistryPath
        AceType = "Deny"
        Principal = "SYSTEM"
        RegistryRights = "Delete"
        AppliesTo = "Object, ChildContainers"
        DependsOn = "[Registry]DscTestKey"
    }

    cRegistryAce DscTestKeyAccessAce2 {
        Path = $RegistryPath
        Ensure = "Absent"
        AceType = "Allow"
        Principal = "Everyone"
        RegistryRights = "CreateKey"
        AppliesTo = "Object"
        DependsOn = "[Registry]DscTestKey"
    }

    cRegistryAce DscTestKeyAuditAce1 {
        Path = $RegistryPath
        AceType = "Audit"
        Principal = "Everyone"
        RegistryRights = "FullControl"
        AuditFlags = "Failure"
        AppliesTo = "Object, ChildContainers"
        DependsOn = "[Registry]DscTestKey"
    }
}