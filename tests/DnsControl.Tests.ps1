#requires -Version 5.1

Describe 'DNS-over-HTTPS template validation' {
    BeforeAll {
        $root = Split-Path -Parent $PSScriptRoot
        . (Join-Path $root 'src/Manifest.ps1')
    }

    It 'accepts absolute https resolver URLs' {
        Test-DnsOverHttpsTemplate -Template 'https://dns.quad9.net/dns-query' | Should -BeTrue
        Test-DnsOverHttpsTemplate -Template 'https://dns.quad9.net' | Should -BeTrue
        Test-DnsOverHttpsTemplate -Template 'https://1.1.1.1/dns-query' | Should -BeTrue
    }

    It 'accepts the {?dns} variable Brave resolver templates use' {
        Test-DnsOverHttpsTemplate -Template 'https://dns.example.com/dns-query{?dns}' | Should -BeTrue
    }

    It 'rejects resolver URLs that are not https' {
        Test-DnsOverHttpsTemplate -Template 'http://dns.quad9.net/dns-query' | Should -BeFalse
        Test-DnsOverHttpsTemplate -Template 'ftp://dns.quad9.net/dns-query' | Should -BeFalse
    }

    It 'rejects a template with no host, which some .NET versions parse as one' {
        Test-DnsOverHttpsTemplate -Template 'https:///dns-query' | Should -BeFalse
        Test-DnsOverHttpsTemplate -Template 'https://' | Should -BeFalse
    }

    It 'rejects values that are not absolute URLs' {
        Test-DnsOverHttpsTemplate -Template 'dns.quad9.net/dns-query' | Should -BeFalse
        Test-DnsOverHttpsTemplate -Template '/dns-query' | Should -BeFalse
        Test-DnsOverHttpsTemplate -Template '   ' | Should -BeFalse
    }
}

Describe 'DNS control plan' {
    BeforeAll {
        $root = Split-Path -Parent $PSScriptRoot
        . (Join-Path $root 'src/Common.ps1')
        . (Join-Path $root 'src/Manifest.ps1')

        $manifest = Get-Content -LiteralPath (Join-Path (Join-Path $root 'config') 'policies.json') -Raw | ConvertFrom-Json
        $policyDefinitions = Get-ManifestMap -Object $manifest.policies
        $modePolicy = [string]$manifest.dnsControl.modePolicy
        $templatesPolicy = [string]$manifest.dnsControl.templatesPolicy
    }

    It 'offers Unmanaged alongside the manifest modes' {
        $names = @(Get-DnsControlModeNames -Manifest $manifest)
        $names | Should -Contain 'Off'
        $names | Should -Contain 'Automatic'
        $names | Should -Contain 'Secure'
        $names | Should -Contain 'Unmanaged'
    }

    It 'removes both policies for Unmanaged and writes none' {
        $plan = Resolve-DnsControlPlan -Manifest $manifest -Mode 'Unmanaged' -PolicyDefinitions $policyDefinitions

        @($plan.RemoveNames) -join ',' | Should -Be "$modePolicy,$templatesPolicy"
        $plan.Definitions.Count | Should -Be 0
    }

    It 'writes the manifest mode value for each mode' {
        (Resolve-DnsControlPlan -Manifest $manifest -Mode 'Off' -PolicyDefinitions $policyDefinitions).Definitions[$modePolicy].value | Should -Be 'off'
        (Resolve-DnsControlPlan -Manifest $manifest -Mode 'Automatic' -PolicyDefinitions $policyDefinitions).Definitions[$modePolicy].value | Should -Be 'automatic'
        (Resolve-DnsControlPlan -Manifest $manifest -Mode 'Secure' -Templates 'https://dns.quad9.net/dns-query' -PolicyDefinitions $policyDefinitions).Definitions[$modePolicy].value | Should -Be 'secure'
    }

    It 'keeps the manifest type and category on each planned policy' {
        $plan = Resolve-DnsControlPlan -Manifest $manifest -Mode 'Secure' -Templates 'https://dns.quad9.net/dns-query' -PolicyDefinitions $policyDefinitions

        $plan.Definitions[$modePolicy].type | Should -Be ([string]$policyDefinitions[$modePolicy].type)
        $plan.Definitions[$modePolicy].category | Should -Be ([string]$policyDefinitions[$modePolicy].category)
        $plan.Definitions[$templatesPolicy].value | Should -Be 'https://dns.quad9.net/dns-query'
    }

    It 'removes a leftover resolver template when no template is given' {
        # Without this, a custom resolver from an earlier run would keep applying.
        $plan = Resolve-DnsControlPlan -Manifest $manifest -Mode 'Automatic' -PolicyDefinitions $policyDefinitions

        @($plan.RemoveNames) -join ',' | Should -Be $templatesPolicy
        $plan.Summary | Should -Be 'Automatic. Brave upgrades to DNS-over-HTTPS when the system resolver supports it.'
    }

    It 'writes no removals when a resolver template is supplied' {
        $plan = Resolve-DnsControlPlan -Manifest $manifest -Mode 'Secure' -Templates 'https://dns.quad9.net/dns-query' -PolicyDefinitions $policyDefinitions

        @($plan.RemoveNames).Count | Should -Be 0
        $plan.Summary | Should -Be 'Secure with resolver https://dns.quad9.net/dns-query.'
    }

    It 'splits whitespace-separated templates and drops duplicates' {
        $plan = Resolve-DnsControlPlan -Manifest $manifest -Mode 'Secure' -Templates 'https://dns.quad9.net/dns-query  https://dns.quad9.net/dns-query   https://cloudflare-dns.com/dns-query' -PolicyDefinitions $policyDefinitions

        $plan.Definitions[$templatesPolicy].value | Should -Be 'https://dns.quad9.net/dns-query https://cloudflare-dns.com/dns-query'
    }

    It 'rejects templates combined with Unmanaged' {
        { Resolve-DnsControlPlan -Manifest $manifest -Mode 'Unmanaged' -Templates 'https://dns.quad9.net/dns-query' -PolicyDefinitions $policyDefinitions } |
            Should -Throw '-DnsOverHttpsTemplates cannot be combined with -DnsOverHttps Unmanaged, which removes the DNS policies instead of setting them.'
    }

    It 'rejects an unknown mode and names the valid ones' {
        $expected = "Unknown DNS-over-HTTPS mode 'Nonsense'. Use one of: $((Get-DnsControlModeNames -Manifest $manifest) -join ', ')."

        { Resolve-DnsControlPlan -Manifest $manifest -Mode 'Nonsense' -PolicyDefinitions $policyDefinitions } | Should -Throw $expected
    }

    It 'rejects templates with Off, which would have no effect' {
        { Resolve-DnsControlPlan -Manifest $manifest -Mode 'Off' -Templates 'https://dns.quad9.net/dns-query' -PolicyDefinitions $policyDefinitions } |
            Should -Throw '-DnsOverHttpsTemplates has no effect with -DnsOverHttps Off. Use Secure or Automatic to set a custom resolver.'
    }

    It 'rejects Secure with no resolver template' {
        { Resolve-DnsControlPlan -Manifest $manifest -Mode 'Secure' -PolicyDefinitions $policyDefinitions } |
            Should -Throw '-DnsOverHttps Secure needs -DnsOverHttpsTemplates with at least one resolver URL, for example -DnsOverHttpsTemplates https://dns.quad9.net/dns-query.'
    }

    It 'rejects a resolver template that is not an https URL' {
        { Resolve-DnsControlPlan -Manifest $manifest -Mode 'Secure' -Templates 'http://dns.quad9.net/dns-query' -PolicyDefinitions $policyDefinitions } |
            Should -Throw 'DNS-over-HTTPS template ''http://dns.quad9.net/dns-query'' is not an https:// URI with a host. Use the resolver''s DoH URL, for example https://dns.quad9.net/dns-query.'
    }

    It 'rejects a manifest whose DNS policies are not in the policy definitions' {
        $partial = @{}
        $partial[$modePolicy] = $policyDefinitions[$modePolicy]

        { Resolve-DnsControlPlan -Manifest $manifest -Mode 'Off' -PolicyDefinitions $partial } |
            Should -Throw "DNS control policy '$templatesPolicy' is missing from config/policies.json."
    }
}
