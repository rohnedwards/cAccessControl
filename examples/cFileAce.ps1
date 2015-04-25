configuration TestFileAceResource {
    Import-DscResource -Module cAccessControl

    $FolderPath = "c:\ps_dsc_test"
    File DscTestFolder {
        DestinationPath = $FolderPath
        Type = "Directory"
    }
    cFileAce DscTestFolderAce1 {
        Path = $FolderPath
        AceType = "Allow"
        Principal = "Everyone"
        FileSystemRights = "Modify"
        AppliesTo = "Object, ChildContainers, ChildObjects"
        DependsOn = "[File]DscTestFolder"
    }
}