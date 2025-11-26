using System.Collections.Generic;

namespace PCAPAnalyzer.UI.Services;

/// <summary>
/// Centralized service for protocol color coding across the application.
/// Provides consistent color schemes for network protocol visualization.
/// </summary>
public class ProtocolColorService : IProtocolColorService
{
    // GitHub-inspired color palette for better visual distinction
    private readonly Dictionary<string, ProtocolColorInfo> _protocolColors = new()
    {
        // Layer 3 Protocols
        { "IP", new ProtocolColorInfo("#58A6FF", "#1F6FEB", "Internet Protocol") },
        { "IPv4", new ProtocolColorInfo("#58A6FF", "#1F6FEB", "Internet Protocol v4") },
        { "IPv6", new ProtocolColorInfo("#539BF5", "#1A66D9", "Internet Protocol v6") },
        { "ICMP", new ProtocolColorInfo("#F78166", "#E5503F", "Internet Control Message Protocol") },
        { "ICMPv6", new ProtocolColorInfo("#F78166", "#E5503F", "ICMPv6") },
        { "ARP", new ProtocolColorInfo("#F0F6FC", "#C9D1D9", "Address Resolution Protocol") },
        { "RARP", new ProtocolColorInfo("#E6EDF3", "#B1B9C1", "Reverse ARP") },

        // Layer 4 Protocols
        { "TCP", new ProtocolColorInfo("#3FB950", "#2EA043", "Transmission Control Protocol") },
        { "UDP", new ProtocolColorInfo("#58A6FF", "#1F6FEB", "User Datagram Protocol") },
        { "SCTP", new ProtocolColorInfo("#56D4DD", "#39C5CF", "Stream Control Transmission Protocol") },

        // Application Layer - Web
        { "HTTP", new ProtocolColorInfo("#A371F7", "#8957E5", "Hypertext Transfer Protocol") },
        { "HTTPS", new ProtocolColorInfo("#8B5CF6", "#7C3AED", "HTTP Secure") },
        { "TLS", new ProtocolColorInfo("#C69026", "#B87A1E", "Transport Layer Security") },
        { "SSL", new ProtocolColorInfo("#C69026", "#B87A1E", "Secure Sockets Layer") },
        { "HTTP/2", new ProtocolColorInfo("#A371F7", "#8957E5", "HTTP/2") },
        { "HTTP/3", new ProtocolColorInfo("#9F7AEA", "#805AD5", "HTTP/3") },
        { "QUIC", new ProtocolColorInfo("#9F7AEA", "#805AD5", "Quick UDP Internet Connections") },

        // Application Layer - DNS
        { "DNS", new ProtocolColorInfo("#FFA657", "#F0883E", "Domain Name System") },
        { "MDNS", new ProtocolColorInfo("#FFB866", "#F59F4D", "Multicast DNS") },
        { "LLMNR", new ProtocolColorInfo("#FFC775", "#F7A95C", "Link-Local Multicast Name Resolution") },

        // Application Layer - Email
        { "SMTP", new ProtocolColorInfo("#D29922", "#C28712", "Simple Mail Transfer Protocol") },
        { "POP3", new ProtocolColorInfo("#DCA732", "#CC9720", "Post Office Protocol") },
        { "IMAP", new ProtocolColorInfo("#E6B542", "#D6A530", "Internet Message Access Protocol") },

        // Application Layer - File Transfer
        { "FTP", new ProtocolColorInfo("#FF7B72", "#F85149", "File Transfer Protocol") },
        { "FTPS", new ProtocolColorInfo("#FF8A80", "#F86058", "FTP Secure") },
        { "SFTP", new ProtocolColorInfo("#FF9388", "#F87068", "SSH File Transfer Protocol") },
        { "TFTP", new ProtocolColorInfo("#FFA294", "#F98078", "Trivial FTP") },
        { "SMB", new ProtocolColorInfo("#FA9D94", "#EA8082", "Server Message Block") },
        { "SMB2", new ProtocolColorInfo("#FAADA4", "#EA9092", "Server Message Block v2") },
        { "NFS", new ProtocolColorInfo("#FABDB4", "#EAA0A2", "Network File System") },

        // Application Layer - Remote Access
        { "SSH", new ProtocolColorInfo("#56D4DD", "#39C5CF", "Secure Shell") },
        { "TELNET", new ProtocolColorInfo("#FF6B6B", "#F04F4F", "Telnet") },
        { "RDP", new ProtocolColorInfo("#6CB6FF", "#4FA3FF", "Remote Desktop Protocol") },
        { "VNC", new ProtocolColorInfo("#7CC4FF", "#60B0FF", "Virtual Network Computing") },

        // Application Layer - Network Management
        { "SNMP", new ProtocolColorInfo("#7EE787", "#56D364", "Simple Network Management Protocol") },
        { "SNMP-TRAP", new ProtocolColorInfo("#8CF590", "#66DD74", "SNMP Trap") },
        { "SYSLOG", new ProtocolColorInfo("#9AFFAD", "#7FE994", "System Logging Protocol") },
        { "NTP", new ProtocolColorInfo("#A8FFC0", "#92F5A8", "Network Time Protocol") },

        // Application Layer - DHCP
        { "DHCP", new ProtocolColorInfo("#7EE787", "#56D364", "Dynamic Host Configuration Protocol") },
        { "DHCPv6", new ProtocolColorInfo("#8CF590", "#66DD74", "DHCPv6") },
        { "BOOTP", new ProtocolColorInfo("#9AFFAD", "#7FE994", "Bootstrap Protocol") },

        // Application Layer - Database
        { "MYSQL", new ProtocolColorInfo("#FFA657", "#F0883E", "MySQL Protocol") },
        { "PGSQL", new ProtocolColorInfo("#58A6FF", "#1F6FEB", "PostgreSQL Protocol") },
        { "MSSQL", new ProtocolColorInfo("#FF9388", "#F87068", "Microsoft SQL Server") },
        { "MONGODB", new ProtocolColorInfo("#7EE787", "#56D364", "MongoDB Protocol") },
        { "REDIS", new ProtocolColorInfo("#FF7B72", "#F85149", "Redis Protocol") },

        // VPN Protocols
        { "OPENVPN", new ProtocolColorInfo("#56D4DD", "#39C5CF", "OpenVPN") },
        { "IPSEC", new ProtocolColorInfo("#6CB6FF", "#4FA3FF", "IPsec") },
        { "ESP", new ProtocolColorInfo("#7CC4FF", "#60B0FF", "Encapsulating Security Payload") },
        { "AH", new ProtocolColorInfo("#8CD4FF", "#70B8FF", "Authentication Header") },
        { "IKE", new ProtocolColorInfo("#9CE4FF", "#80C8FF", "Internet Key Exchange") },
        { "L2TP", new ProtocolColorInfo("#ACF4FF", "#90D8FF", "Layer 2 Tunneling Protocol") },
        { "PPTP", new ProtocolColorInfo("#BCFFFF", "#A0E8FF", "Point-to-Point Tunneling Protocol") },

        // Routing Protocols
        { "OSPF", new ProtocolColorInfo("#A371F7", "#8957E5", "Open Shortest Path First") },
        { "BGP", new ProtocolColorInfo("#B381F7", "#9967E5", "Border Gateway Protocol") },
        { "RIP", new ProtocolColorInfo("#C391F7", "#A977E5", "Routing Information Protocol") },
        { "EIGRP", new ProtocolColorInfo("#D3A1F7", "#B987E5", "Enhanced Interior Gateway Routing Protocol") },

        // Streaming Protocols
        { "RTP", new ProtocolColorInfo("#FF9388", "#F87068", "Real-time Transport Protocol") },
        { "RTCP", new ProtocolColorInfo("#FFA394", "#F98078", "RTP Control Protocol") },
        { "RTSP", new ProtocolColorInfo("#FFB3A4", "#FA9088", "Real Time Streaming Protocol") },
        { "RTMP", new ProtocolColorInfo("#FFC3B4", "#FBA098", "Real-Time Messaging Protocol") },

        // VoIP Protocols
        { "SIP", new ProtocolColorInfo("#FFA657", "#F0883E", "Session Initiation Protocol") },
        { "H.323", new ProtocolColorInfo("#FFB866", "#F59F4D", "H.323") },
        { "MGCP", new ProtocolColorInfo("#FFC775", "#F7A95C", "Media Gateway Control Protocol") },

        // IoT Protocols
        { "MQTT", new ProtocolColorInfo("#7EE787", "#56D364", "Message Queuing Telemetry Transport") },
        { "COAP", new ProtocolColorInfo("#8CF590", "#66DD74", "Constrained Application Protocol") },
        { "AMQP", new ProtocolColorInfo("#9AFFAD", "#7FE994", "Advanced Message Queuing Protocol") },

        // Other/Unknown
        { "OTHER", new ProtocolColorInfo("#6B7280", "#4B5563", "Other Protocol") },
        { "UNKNOWN", new ProtocolColorInfo("#4B5563", "#374151", "Unknown Protocol") }
    };

    /// <summary>
    /// Get color information for a specific protocol.
    /// </summary>
    public ProtocolColorInfo GetProtocolColor(string protocol)
    {
        if (string.IsNullOrWhiteSpace(protocol))
            return _protocolColors["UNKNOWN"];

        var protocolUpper = protocol.ToUpperInvariant();

        // Direct match
        if (_protocolColors.TryGetValue(protocolUpper, out var color))
            return color;

        // Partial match for compound protocols (e.g., "TCP/HTTP")
        foreach (var kvp in _protocolColors)
        {
            if (protocolUpper.Contains(kvp.Key, StringComparison.Ordinal))
                return kvp.Value;
        }

        // Default to "OTHER"
        return _protocolColors["OTHER"];
    }

    /// <summary>
    /// Get hex color code for a protocol (for chart/UI use).
    /// </summary>
    public string GetProtocolColorHex(string protocol)
    {
        return GetProtocolColor(protocol).PrimaryColor;
    }

    /// <summary>
    /// Get all available protocol colors for legend display.
    /// </summary>
    public Dictionary<string, ProtocolColorInfo> GetAllProtocolColors()
    {
        return new Dictionary<string, ProtocolColorInfo>(_protocolColors);
    }

    /// <summary>
    /// Get protocol colors for most common protocols (for simplified UI).
    /// </summary>
    public Dictionary<string, ProtocolColorInfo> GetCommonProtocolColors()
    {
        return new Dictionary<string, ProtocolColorInfo>
        {
            { "TCP", _protocolColors["TCP"] },
            { "UDP", _protocolColors["UDP"] },
            { "ICMP", _protocolColors["ICMP"] },
            { "HTTP", _protocolColors["HTTP"] },
            { "HTTPS", _protocolColors["HTTPS"] },
            { "DNS", _protocolColors["DNS"] },
            { "TLS", _protocolColors["TLS"] },
            { "SSH", _protocolColors["SSH"] },
            { "FTP", _protocolColors["FTP"] },
            { "SMTP", _protocolColors["SMTP"] },
            { "OTHER", _protocolColors["OTHER"] }
        };
    }

    /// <summary>
    /// Get protocol category for grouping.
    /// </summary>
    public string GetProtocolCategory(string protocol)
    {
        if (string.IsNullOrWhiteSpace(protocol))
            return "Unknown";

        var protocolUpper = protocol.ToUpperInvariant();

        // Layer 3
        if (new[] { "IP", "IPv4", "IPv6", "ICMP", "ICMPv6", "ARP", "RARP" }.Contains(protocolUpper))
            return "Network Layer";

        // Layer 4
        if (new[] { "TCP", "UDP", "SCTP" }.Contains(protocolUpper))
            return "Transport Layer";

        // Web
        if (new[] { "HTTP", "HTTPS", "TLS", "SSL", "HTTP/2", "HTTP/3", "QUIC" }.Contains(protocolUpper))
            return "Web";

        // Email
        if (new[] { "SMTP", "POP3", "IMAP" }.Contains(protocolUpper))
            return "Email";

        // File Transfer
        if (new[] { "FTP", "FTPS", "SFTP", "TFTP", "SMB", "SMB2", "NFS" }.Contains(protocolUpper))
            return "File Transfer";

        // Remote Access
        if (new[] { "SSH", "TELNET", "RDP", "VNC" }.Contains(protocolUpper))
            return "Remote Access";

        // Network Management
        if (new[] { "SNMP", "SNMP-TRAP", "SYSLOG", "NTP", "DHCP", "DHCPv6", "BOOTP" }.Contains(protocolUpper))
            return "Network Management";

        // Database
        if (new[] { "MYSQL", "PGSQL", "MSSQL", "MONGODB", "REDIS" }.Contains(protocolUpper))
            return "Database";

        // VPN
        if (new[] { "OPENVPN", "IPSEC", "ESP", "AH", "IKE", "L2TP", "PPTP" }.Contains(protocolUpper))
            return "VPN";

        // Routing
        if (new[] { "OSPF", "BGP", "RIP", "EIGRP" }.Contains(protocolUpper))
            return "Routing";

        // Streaming
        if (new[] { "RTP", "RTCP", "RTSP", "RTMP" }.Contains(protocolUpper))
            return "Streaming";

        // VoIP
        if (new[] { "SIP", "H.323", "MGCP" }.Contains(protocolUpper))
            return "VoIP";

        // IoT
        if (new[] { "MQTT", "COAP", "AMQP" }.Contains(protocolUpper))
            return "IoT";

        // DNS
        if (new[] { "DNS", "MDNS", "LLMNR" }.Contains(protocolUpper))
            return "DNS";

        return "Application Layer";
    }
}

/// <summary>
/// Interface for protocol color service.
/// </summary>
public interface IProtocolColorService
{
    ProtocolColorInfo GetProtocolColor(string protocol);
    string GetProtocolColorHex(string protocol);
    Dictionary<string, ProtocolColorInfo> GetAllProtocolColors();
    Dictionary<string, ProtocolColorInfo> GetCommonProtocolColors();
    string GetProtocolCategory(string protocol);
}

/// <summary>
/// Color information for a protocol including primary, hover, and description.
/// </summary>
public class ProtocolColorInfo
{
    public string PrimaryColor { get; set; }
    public string HoverColor { get; set; }
    public string Description { get; set; }

    public ProtocolColorInfo(string primaryColor, string hoverColor, string description)
    {
        PrimaryColor = primaryColor;
        HoverColor = hoverColor;
        Description = description;
    }
}
