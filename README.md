# cAccessControl
Provides access control resources using native PowerShell and .NET (no dependency on PowerShell Access Control module).

Right now, it supports files and folders (cFileAce) and registry keys (cRegistryAce).

This requires WMF 5.0 because the resources are all class based (I actually created this module because I had never actually written class based resources).
