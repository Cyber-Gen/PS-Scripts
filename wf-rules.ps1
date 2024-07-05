<#
.SYNOPSIS
	Searches Windows Defender Firewall rules based on various filters.

.DESCRIPTION
	This script allows users to search for Windows Defender Firewall rules using multiple filters such as rule type, enabled state, name, profile, protocol, local port, remote port, local address, remote address, and program.

.PARAMETER RuleType
	Type of rules to search for. Options: All, Inbound, Outbound. Default is All.

.PARAMETER Enabled
	Filter based on whether the rule is enabled or not. Options: Yes, No. By default, searches both.

.PARAMETER Name
	Name of the rule to search for. Supports partial, case-insensitive matching.

.PARAMETER Profile
	Profile to filter by. Options: All, Public, Private, Domain. Default is All.

.PARAMETER Protocol
	Protocol to filter by. Options: Any, TCP, UDP. Default is Any.

.PARAMETER LocalPort
	Local port to filter by. Any valid port number (0 to 65535) or 'Any'. Default is Any.

.PARAMETER RemotePort
	Remote port to filter by. Can be a single port, a range (e.g., 1000-2000), or 'Any'. Default is Any.

.PARAMETER LocalAddress
	Local address to filter by. Accepts any valid input address or 'Any'. Default is Any.

.PARAMETER RemoteAddress
	Remote address to filter by. Accepts any valid input address or 'Any'. Default is Any.

.PARAMETER Program
	Program to filter by. Accepts a valid program path, name, or 'Any'. Default is Any.

.EXAMPLE
	.\wf-rules.ps1 -RuleType Inbound -Enabled Yes -Profile Public -Protocol TCP
	Searches for all enabled inbound rules for the public profile using TCP protocol.
#>

param(
	[switch]$h,
	[ValidateSet("All", "Inbound", "Outbound")]
	[string]$RuleType = "All",
	[ValidateSet("Yes", "No", "All")]
	[string]$Enabled = "All",
	[string]$Name = "",
	[ValidateSet("All", "Public", "Private", "Domain")]
	[string]$ProfileFilter = "All",
	[string]$Protocol = "Any",
	[string]$LocalPort = "Any",
	[string]$RemotePort = "Any",
	[string]$LocalAddress = "Any",
	[string]$RemoteAddress = "Any",
	[string]$Program = "Any"
)

if ($PSBoundParameters.ContainsKey('h')) {
	Get-Help .\wf-rules.ps1 -Full
	exit
}

function Get-WFRules {
	$rules = Get-NetFirewallRule | Where-Object {
		if ($RuleType -ne "All") {
			$_.Direction -eq $RuleType
		} else {
			$true
		}
	} | Where-Object {
		if ($Enabled -ne "All") {
			$_.Enabled -eq ($Enabled -eq "Yes")
		} else {
			$true
		}
	} | Where-Object {
		if ($Name) {
			$_.DisplayName -like "*$Name*"
		} else {
			$true
		}
	} | Where-Object {
		if ($ProfileFilter -ne "All") {
			$_.Profile.ToString() -eq $ProfileFilter
		} else {
			$true
		}
	}

    $filteredRules = foreach ($rule in $rules) {
        $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule
        $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule
        $appFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule
        $protocolMatch = $Protocol -eq "Any" -or $portFilter.Protocol -eq $Protocol
        $localPortMatch = $LocalPort -eq "Any" -or $portFilter.LocalPort -match $LocalPort
        $remotePortMatch = $RemotePort -eq "Any" -or $portFilter.RemotePort -match $RemotePort
        $localAddressMatch = $LocalAddress -eq "Any" -or $addressFilter.LocalAddress -match $LocalAddress
        $remoteAddressMatch = $RemoteAddress -eq "Any" -or $addressFilter.RemoteAddress -match $RemoteAddress
        $programMatch = $Program -eq "Any" -or $appFilter.Program -like $Program
        if ($protocolMatch -and $localPortMatch -and $remotePortMatch -and $localAddressMatch -and $remoteAddressMatch -and $programMatch) {
            $rule | Select-Object DisplayName, Direction, Enabled, Profile, @{Name="Protocol";Expression={$portFilter.Protocol}}, @{Name="LocalPort";Expression={$portFilter.LocalPort}}, @{Name="RemotePort";Expression={$portFilter.RemotePort}}, @{Name="LocalAddress";Expression={$addressFilter.LocalAddress}}, @{Name="RemoteAddress";Expression={$addressFilter.RemoteAddress}}, @{Name="Program";Expression={if ($appFilter.Program) { Split-Path $appFilter.Program -Leaf } else { "N/A" }}}
        }
    }
    $filteredRules | Format-Table -AutoSize
}

Get-WFRules