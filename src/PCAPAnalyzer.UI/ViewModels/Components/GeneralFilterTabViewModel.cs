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
/// NOTE: Security filters moved to Threats tab, TCP quality filters moved to Anomalies tab
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

        // TCP flags chips (connection state analysis)
        var tcpFlags = new[] { "SYN", "SYN-ACK", "RST", "FIN", "PSH", "ACK-only", "URG" };
        foreach (var f in tcpFlags)
            TcpFlagsChips.Add(new FilterChipViewModel(f));

        // L7 Application protocol chips (core + network services)
        // NOTE: Telnet moved to Threats tab (insecure protocol)
        var apps = new[] { "DNS", "HTTP", "HTTPS", "SSH", "FTP", "SMTP", "SNMP", "STUN", "DHCP" };
        foreach (var a in apps)
            ApplicationChips.Add(new FilterChipViewModel(a));
    }

    public void SetMode(FilterChipMode mode)
    {
        foreach (var chip in ProtocolChips) chip.SetMode(mode);
        foreach (var chip in NetworkChips) chip.SetMode(mode);
        foreach (var chip in TcpFlagsChips) chip.SetMode(mode);
        foreach (var chip in ApplicationChips) chip.SetMode(mode);
    }

    public (List<string> Protocols, List<string> QuickFilters) GetPendingFilters()
    {
        return (
            ProtocolChips.Concat(ApplicationChips).Where(c => c.IsSelected).Select(c => c.Name).ToList(),
            NetworkChips.Concat(TcpFlagsChips).Where(c => c.IsSelected).Select(c => c.Name).ToList()
        );
    }

    public void Reset()
    {
        foreach (var chip in ProtocolChips) chip.Reset();
        foreach (var chip in NetworkChips) chip.Reset();
        foreach (var chip in TcpFlagsChips) chip.Reset();
        foreach (var chip in ApplicationChips) chip.Reset();
    }
}
