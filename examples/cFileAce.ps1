configuration TestFileAceResource {
    Import-DscResource -Module cAccessControl

    File DscTestFolder {
        DestinationPath = "c:\ps_dsc_test"
        Type = "Directory"
    }
    cFileAce DscTestFolderAce1 {
        Path = "c:\powershell"
        AceType = "Allow"
        Principal = "Everyone"
        FileSystemRights = "Modify"
        AppliesTo = "Object, ChildContainers, ChildObjects"
        DependsOn = "[File]DscTestFolder"
    }
}