using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Filter tab for General/Packet Analysis view.
/// Organizes filters into logical groups matching network analyst mental model:
/// - L4 Protocols: TCP, UDP, ICMP, ARP, IGMP, GRE
/// - Network: IP version (IPv4/IPv6), address scope (RFC1918/Public), delivery (Unicast/Multicast/Broadcast)
/// - TCP Flags: SYN, SYN-ACK, RST, FIN, PSH, ACK-only, URG
/// - Application: L7 protocols (DNS, HTTP, HTTPS, SSH, FTP, SMTP, SNMP, STUN, DHCP)
/// - Security: Deprecated crypto (TLSv1.0, TLSv1.1, ObsoleteCrypto, SSHv1, SmbV1), CleartextAuth, Insecure
/// </summary>
public partial class GeneralFilterTabViewModel : ObservableObject
{
    // NOTE: IP/Port inputs moved to UnifiedFilterPanelViewModel (shared across all tabs)

    /// <summary>L4 protocols: TCP, UDP, ICMP, ARP, IGMP, GRE</summary>
    public ObservableCollection<FilterChipViewModel> ProtocolChips { get; } = [];

    /// <summary>
    /// Network type filters organized by:
    /// - Version: IPv4, IPv6
    /// - Scope: RFC1918, Public, APIPA, Loopback, LinkLocal, Anycast
    /// - Delivery: Unicast, Multicast, Broadcast
    /// </summary>
    public ObservableCollection<FilterChipViewModel> NetworkChips { get; } = [];

    /// <summary>TCP flags: SYN, SYN-ACK, RST, FIN, PSH, ACK-only, URG</summary>
    public ObservableCollection<FilterChipViewModel> TcpFlagsChips { get; } = [];

    /// <summary>L7 Application protocols: DNS, HTTP, HTTPS, SSH, FTP, SMTP, SNMP, STUN, DHCP</summary>
    public ObservableCollection<FilterChipViewModel> ApplicationChips { get; } = [];

    /// <summary>
    /// Security filters: Deprecated crypto, cleartext auth, insecure protocols
    /// Moved from Threats tab for immediate visibility during packet analysis
    /// </summary>
    public ObservableCollection<FilterChipViewModel> SecurityChips { get; } = [];

    public GeneralFilterTabViewModel()
    {
        InitializeChips();
    }

    private void InitializeChips()
    {
        // L4 Protocol chips (transport layer)
        var protocols = new[] { "TCP", "UDP", "ICMP", "ARP", "IGMP", "GRE" };
        foreach (var p in protocols)
            ProtocolChips.Add(new FilterChipViewModel(p));

        // Network type chips (logically grouped: Version → Scope → Delivery)
        // Matches SmartFilterBuilderService IP ADDRESS CLASSIFICATION section
        var networkTypes = new[]
        {
            // IP Version
            "IPv4", "IPv6",
            // Address Scope
            "RFC1918", "Public", "APIPA", "Loopback", "LinkLocal", "Anycast",
            // Delivery Method
            "Unicast", "Multicast", "Broadcast"
        };
        foreach (var n in networkTypes)
            NetworkChips.Add(new FilterChipViewModel(n));

        // TCP flags chips (connection state analysis) - all flags now exposed
        var tcpFlags = new[] { "SYN", "SYN-ACK", "RST", "FIN", "PSH", "ACK-only", "URG" };
        foreach (var f in tcpFlags)
            TcpFlagsChips.Add(new FilterChipViewModel(f));

        // L7 Application protocol chips (core + network services)
        // TLS moved to SecurityChips since it's about encryption security
        var apps = new[] { "DNS", "HTTP", "HTTPS", "SSH", "FTP", "SMTP", "SNMP", "STUN", "DHCP" };
        foreach (var a in apps)
            ApplicationChips.Add(new FilterChipViewModel(a));

        // Security chips (deprecated crypto, cleartext auth, insecure protocols)
        // Grouped per user request: TLS with security-related filters
        var security = new[]
        {
            "TlsV10", "TlsV11",           // Deprecated TLS (⚠️ per RFC 8996)
            "ObsoleteCrypto",              // Combined SSL + deprecated TLS
            "SSHv1", "SmbV1",              // Deprecated protocols
            "CleartextAuth", "Insecure"    // Authentication risks
        };
        foreach (var s in security)
            SecurityChips.Add(new FilterChipViewModel(s));
    }

    public void SetMode(FilterChipMode mode)
    {
        foreach (var chip in ProtocolChips) chip.SetMode(mode);
        foreach (var chip in NetworkChips) chip.SetMode(mode);
        foreach (var chip in TcpFlagsChips) chip.SetMode(mode);
        foreach (var chip in ApplicationChips) chip.SetMode(mode);
        foreach (var chip in SecurityChips) chip.SetMode(mode);
    }

    public (List<string> Protocols, List<string> QuickFilters) GetPendingFilters()
    {
        var allChips = ProtocolChips
            .Concat(NetworkChips)
            .Concat(TcpFlagsChips)
            .Concat(ApplicationChips)
            .Concat(SecurityChips);

        return (
            ProtocolChips.Concat(ApplicationChips).Where(c => c.IsSelected).Select(c => c.Name).ToList(),
            NetworkChips.Concat(TcpFlagsChips).Concat(SecurityChips).Where(c => c.IsSelected).Select(c => c.Name).ToList()
        );
    }

    public void Reset()
    {
        foreach (var chip in ProtocolChips) chip.Reset();
        foreach (var chip in NetworkChips) chip.Reset();
        foreach (var chip in TcpFlagsChips) chip.Reset();
        foreach (var chip in ApplicationChips) chip.Reset();
        foreach (var chip in SecurityChips) chip.Reset();
    }
}
