#requires -Version 5.1

Describe 'Backup policy kind validation' {
    BeforeAll {
        $root = Split-Path -Parent $PSScriptRoot
        . (Join-Path $root 'src/Common.ps1')
        . (Join-Path $root 'src/PlatformPolicy.ps1')
        . (Join-Path $root 'src/Backup.ps1')

        $linuxDefault = '/etc/brave/policies/managed/BraveDebloater.json'
        $macPlist = '/Library/Managed Preferences/com.brave.Browser.plist'
        $machineKey = 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\BraveSoftware\Brave'
        $userKey = 'Registry::HKEY_CURRENT_USER\Software\Policies\BraveSoftware\Brave'
    }

    It 'accepts each kind at its own platform path' {
        { Assert-BackupPolicyKind -Backup ([pscustomobject]@{ policyKind = 'Registry' }) -RegistryPath $machineKey } | Should -Not -Throw
        { Assert-BackupPolicyKind -Backup ([pscustomobject]@{ policyKind = 'JsonFile' }) -RegistryPath $linuxDefault } | Should -Not -Throw
        { Assert-BackupPolicyKind -Backup ([pscustomobject]@{ policyKind = 'MacOSPlist' }) -RegistryPath $macPlist } | Should -Not -Throw
        { Assert-BackupPolicyKind -Backup ([pscustomobject]@{ policyKind = 'MacOSDefaults' }) -RegistryPath 'com.brave.Browser' } | Should -Not -Throw
    }

    It 'treats a backup with no recorded kind as Registry' {
        # Backups written before policyKind existed have no such property.
        { Assert-BackupPolicyKind -Backup ([pscustomobject]@{ schemaVersion = 1 }) -RegistryPath $userKey } | Should -Not -Throw
    }

    It 'accepts a file kind at the -PolicyPath passed for this restore' {
        $override = Join-Path ([System.IO.Path]::GetTempPath()) 'BraveDebloater-override.json'

        { Assert-BackupPolicyKind -Backup ([pscustomobject]@{ policyKind = 'JsonFile' }) -RegistryPath $override -AllowedPolicyPath $override } | Should -Not -Throw
    }

    It 'rejects an unknown kind before writing anything' {
        { Assert-BackupPolicyKind -Backup ([pscustomobject]@{ policyKind = 'Whatever' }) -RegistryPath $machineKey } |
            Should -Throw "Backup has unsupported policy kind 'Whatever'. Restore stopped before writing anything."
    }

    It 'rejects a Registry kind pointed at a file path' {
        # A tampered backup must not turn a registry key name into a file write.
        { Assert-BackupPolicyKind -Backup ([pscustomobject]@{ policyKind = 'Registry' }) -RegistryPath $linuxDefault } |
            Should -Throw "Backup policy kind 'Registry' does not match its policy path '$linuxDefault'. Restore stopped before writing anything."
    }

    It 'rejects a JsonFile kind pointed at a registry key' {
        { Assert-BackupPolicyKind -Backup ([pscustomobject]@{ policyKind = 'JsonFile' }) -RegistryPath $machineKey } |
            Should -Throw "Backup policy kind 'JsonFile' does not match its policy path '$machineKey'. Restore stopped before writing anything."
    }

    It 'rejects a file kind pointed at the other platform default' {
        { Assert-BackupPolicyKind -Backup ([pscustomobject]@{ policyKind = 'JsonFile' }) -RegistryPath $macPlist } |
            Should -Throw "Backup policy kind 'JsonFile' does not match its policy path '$macPlist'. Restore stopped before writing anything."

        { Assert-BackupPolicyKind -Backup ([pscustomobject]@{ policyKind = 'MacOSPlist' }) -RegistryPath $linuxDefault } |
            Should -Throw "Backup policy kind 'MacOSPlist' does not match its policy path '$linuxDefault'. Restore stopped before writing anything."
    }

    It 'rejects a file kind at a path that was not allowed for this restore' {
        $elsewhere = Join-Path ([System.IO.Path]::GetTempPath()) 'BraveDebloater-elsewhere.json'

        { Assert-BackupPolicyKind -Backup ([pscustomobject]@{ policyKind = 'JsonFile' }) -RegistryPath $elsewhere -AllowedPolicyPath (Join-Path ([System.IO.Path]::GetTempPath()) 'BraveDebloater-override.json') } |
            Should -Throw "Backup policy kind 'JsonFile' does not match its policy path '$elsewhere'. Restore stopped before writing anything."
    }

    It 'rejects a MacOSDefaults kind pointed at a file path' {
        { Assert-BackupPolicyKind -Backup ([pscustomobject]@{ policyKind = 'MacOSDefaults' }) -RegistryPath $linuxDefault } |
            Should -Throw "Backup policy kind 'MacOSDefaults' does not match its policy path '$linuxDefault'. Restore stopped before writing anything."
    }
}
