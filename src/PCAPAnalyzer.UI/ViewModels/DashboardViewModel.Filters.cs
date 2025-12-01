using System.Collections.Generic;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// DashboardViewModel partial - Smart Filter Helper Methods
/// Delegates to centralized NetworkFilterHelper for consistency.
/// </summary>
public partial class DashboardViewModel
{
    // ==================== TAB-SPECIFIC QUICK FILTER OVERRIDES ====================

    /// <summary>
    /// Returns ONLY Dashboard-specific filter mappings for chip creation.
    /// These are L7 protocols, TLS versions, and VPN protocols that don't exist in NetworkQuickFilters.
    ///
    /// ARCHITECTURE NOTE:
    /// - Shared filters (Network, Security, Traffic, TCP Perf, etc.) are handled by the
    ///   base class GetActiveQuickFilterMappings() which reads from NetworkQuickFilters.
    /// - This method returns ONLY Dashboard-specific filters to avoid duplicate chips.
    /// </summary>
    protected override List<(string DisplayName, string CodeName)> GetTabSpecificQuickFilterMappings()
    {
        var result = new List<(string, string)>();

        // ==================== L7 PROTOCOL FILTERS (Dashboard-only) ====================
        if (FilterTlsV10Toggle) result.Add(("TLS 1.0", "TlsV10"));
        if (FilterTlsV11Toggle) result.Add(("TLS 1.1", "TlsV11"));
        if (FilterTlsV12Toggle) result.Add(("TLS 1.2", "TlsV12"));
        if (FilterTlsV13Toggle) result.Add(("TLS 1.3", "TlsV13"));
        if (FilterHttpToggle) result.Add(("HTTP", "HTTP"));
        if (FilterHttpsToggle) result.Add(("HTTPS", "HTTPS"));
        if (FilterDnsToggle) result.Add(("DNS", "DNS"));
        if (FilterSnmpToggle) result.Add(("SNMP", "SNMP"));
        if (FilterSshToggle) result.Add(("SSH", "SSH"));
        if (FilterFtpToggle) result.Add(("FTP", "FTP"));
        if (FilterSmtpToggle) result.Add(("SMTP", "SMTP"));
        if (FilterStunToggle) result.Add(("STUN", "STUN"));
        if (FilterDhcpServerToggle) result.Add(("DHCP", "DHCP"));

        // ==================== VPN PROTOCOL FILTERS (Dashboard-only) ====================
        if (FilterWireGuardToggle) result.Add(("WireGuard", "WireGuard"));
        if (FilterOpenVpnToggle) result.Add(("OpenVPN", "OpenVPN"));
        if (FilterIkeV2Toggle) result.Add(("IKEv2", "IKEv2"));
        if (FilterIpsecToggle) result.Add(("IPSec", "IPSec"));
        if (FilterL2tpToggle) result.Add(("L2TP", "L2TP"));
        if (FilterPptpToggle) result.Add(("PPTP", "PPTP"));

        return result;
    }

    /// <summary>
    /// Untoggles Dashboard-specific filters only.
    /// Returns true if the filter was handled, false to let base class handle it.
    /// </summary>
    protected override bool UnToggleTabSpecificFilter(string codeName)
    {
        switch (codeName)
        {
            // L7 Protocol Filters (Dashboard-only)
            case "TlsV10": FilterTlsV10Toggle = false; return true;
            case "TlsV11": FilterTlsV11Toggle = false; return true;
            case "TlsV12": FilterTlsV12Toggle = false; return true;
            case "TlsV13": FilterTlsV13Toggle = false; return true;
            case "HTTP": FilterHttpToggle = false; return true;
            case "HTTPS": FilterHttpsToggle = false; return true;
            case "DNS": FilterDnsToggle = false; return true;
            case "SNMP": FilterSnmpToggle = false; return true;
            case "SSH": FilterSshToggle = false; return true;
            case "FTP": FilterFtpToggle = false; return true;
            case "SMTP": FilterSmtpToggle = false; return true;
            case "STUN": FilterStunToggle = false; return true;
            case "DHCP": FilterDhcpServerToggle = false; return true;

            // VPN Protocol Filters (Dashboard-only)
            case "WireGuard": FilterWireGuardToggle = false; return true;
            case "OpenVPN": FilterOpenVpnToggle = false; return true;
            case "IKEv2": FilterIkeV2Toggle = false; return true;
            case "IPSec": FilterIpsecToggle = false; return true;
            case "L2TP": FilterL2tpToggle = false; return true;
            case "PPTP": FilterPptpToggle = false; return true;

            // Shared filters are handled by base class UnToggleQuickFilter()
            default: return false;
        }
    }

    // ==================== SMART FILTER HELPER METHODS ====================
    // All methods delegate to centralized NetworkFilterHelper for consistency

    private static bool IsRFC1918(string ip) => NetworkFilterHelper.IsRFC1918(ip);

    private static bool IsPrivateIP(string ip) =>
        NetworkFilterHelper.IsRFC1918(ip) ||
        NetworkFilterHelper.IsLoopback(ip) ||
        NetworkFilterHelper.IsLinkLocal(ip);

    private static bool IsAPIPA(string ip) => NetworkFilterHelper.IsLinkLocal(ip);

    private static bool IsIPv4(string ip) => NetworkFilterHelper.IsIPv4(ip);

    private static bool IsIPv6(string ip) => NetworkFilterHelper.IsIPv6(ip);

    private static bool IsMulticast(string ip) => NetworkFilterHelper.IsMulticast(ip);

    private static bool IsBroadcast(string ip) => NetworkFilterHelper.IsBroadcast(ip);

    private static bool IsAnycast(string ip) => NetworkFilterHelper.IsAnycast(ip);

    private static bool IsInsecureProtocol(PacketInfo p) =>
        NetworkFilterHelper.IsInsecureProtocol(p.L7Protocol ?? p.Protocol.ToString());
}
