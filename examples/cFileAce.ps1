configuration TestFileAceResource {
    Import-DscResource -Module cAccessControl

    $FolderPath = "c:\ps_dsc_test"
    File DscTestFolder {
        DestinationPath = $FolderPath
        Type = "Directory"
    }

    cFileAce DscTestFolderAccessAce1 {
        Path = $FolderPath
        Ensure = "Absent"
        AceType = "Allow"
        Principal = "Everyone"
        FileSystemRights = "Delete, DeleteSubdirectoriesAndFiles, TakeOwnership"
        AppliesTo = "Object"
        DependsOn = "[File]DscTestFolder"
    }

    cFileAce DscTestFolderAccessAce2 {
        Path = $FolderPath
        Ensure = "Absent"
        AceType = "Allow"
        Principal = "Everyone"
        FileSystemRights = "Write, Synchronize"
        AppliesTo = "Object, ChildContainers, ChildObjects"
        Specific = $true
        DependsOn = "[File]DscTestFolder"
    }

    cFileAce DscTestFolderAccessAce3 {
        Path = $FolderPath
        Ensure = "Present"
        AceType = "Allow"
        Principal = "Users"
        FileSystemRights = "ReadAndExecute, Synchronize"
        AppliesTo = "Object, ChildContainers, ChildObjects"
        Specific = $true
        DependsOn = "[File]DscTestFolder"
    }

    cFileAce DscTestFolderAccessAce4 {
        Path = $FolderPath
        Ensure = "Present"
        AceType = "Allow"
        Principal = "Administrators"
        FileSystemRights = "TakeOwnership, Synchronize"
        AppliesTo = "Object"
        Specific = $true
        DependsOn = "[File]DscTestFolder"
    }

    cFileAce DscTestFolderAccessAce5 {
        Path = $FolderPath
        Ensure = "Present"
        AceType = "Allow"
        Principal = "Administrators"
        FileSystemRights = "FullControl"
        AppliesTo = "Object, ChildContainers, ChildObjects"
        IgnoreInheritedAces = $true
        DependsOn = "[File]DscTestFolder"
    }

    cFileAce DscTestFolderAuditAce1 {
        Path = $FolderPath
        AceType = "Audit"
        Principal = "Everyone"
        FileSystemRights = "FullControl"
        AuditFlags = "Failure"
        AppliesTo = "Object, ChildContainers, ChildObjects"
        DependsOn = "[File]DscTestFolder"
    }

    cFileAce DscTestFolderAuditAce2 {
        Path = $FolderPath
        AceType = "Audit"
        Principal = "Administrators"
        FileSystemRights = "ChangePermissions"
        AuditFlags = "Success, Failure"
        AppliesTo = "Object"
        DependsOn = "[File]DscTestFolder"
    }

}