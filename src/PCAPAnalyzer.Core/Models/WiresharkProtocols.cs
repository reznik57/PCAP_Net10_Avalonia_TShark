using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Models;

/// <summary>
/// Comprehensive list of protocols recognized by Wireshark
/// Organized by category for better management
/// </summary>
public static class WiresharkProtocols
{
    // Network Layer Protocols
    public static readonly List<string> NetworkProtocols = new()
    {
        "IP", "IPv4", "IPv6", "ICMP", "ICMPv6", "IGMP", "OSPF", "BGP", "RIP", "EIGRP", "IS-IS"
    };

    // Transport Layer Protocols  
    public static readonly List<string> TransportProtocols = new()
    {
        "TCP", "UDP", "SCTP", "DCCP", "QUIC"
    };

    // Application Layer - Web & HTTP
    public static readonly List<string> WebProtocols = new()
    {
        "HTTP", "HTTPS", "HTTP2", "HTTP3", "WebSocket", "SPDY"
    };

    // Application Layer - Email
    public static readonly List<string> EmailProtocols = new()
    {
        "SMTP", "POP", "POP3", "IMAP", "IMAP4"
    };

    // Application Layer - File Transfer
    public static readonly List<string> FileTransferProtocols = new()
    {
        "FTP", "FTPS", "SFTP", "TFTP", "SMB", "SMB2", "SMB3", "CIFS", "NFS", "AFP"
    };

    // Application Layer - Remote Access
    public static readonly List<string> RemoteAccessProtocols = new()
    {
        "SSH", "Telnet", "RDP", "RDPUDP", "VNC", "X11"
    };

    // Application Layer - Directory Services
    public static readonly List<string> DirectoryProtocols = new()
    {
        "LDAP", "LDAPS", "Kerberos", "RADIUS", "TACACS", "TACACS+"
    };

    // Application Layer - DNS & Name Resolution
    public static readonly List<string> NameResolutionProtocols = new()
    {
        "DNS", "mDNS", "LLMNR", "NBNS", "NetBIOS", "WINS"
    };

    // Application Layer - Network Management
    public static readonly List<string> ManagementProtocols = new()
    {
        "SNMP", "SNMPv2", "SNMPv3", "SYSLOG", "NetFlow", "sFlow", "IPFIX"
    };

    // Application Layer - VoIP & Multimedia
    public static readonly List<string> VoIPProtocols = new()
    {
        "SIP", "RTP", "RTCP", "RTSP", "H.323", "MGCP", "Skinny", "IAX2"
    };

    // Application Layer - Database
    public static readonly List<string> DatabaseProtocols = new()
    {
        "MySQL", "PostgreSQL", "MSSQL", "Oracle", "MongoDB", "Redis", "Cassandra"
    };

    // Security & VPN Protocols
    public static readonly List<string> SecurityProtocols = new()
    {
        "TLS", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3", "SSL", "SSLv2", "SSLv3",
        "IPSec", "IKE", "IKEv2", "ISAKMP", "ESP", "AH",
        "OpenVPN", "WireGuard", "L2TP", "PPTP", "GRE"
    };

    // Layer 2 Protocols
    public static readonly List<string> Layer2Protocols = new()
    {
        "Ethernet", "ARP", "RARP", "STP", "RSTP", "VLAN", "802.1Q", "LLDP", "CDP", "EAP", "PPP", "PPPoE"
    };

    // Routing Protocols
    public static readonly List<string> RoutingProtocols = new()
    {
        "OSPF", "BGP", "RIP", "RIPv2", "EIGRP", "IS-IS", "VRRP", "HSRP", "GLBP"
    };

    // Microsoft Protocols
    public static readonly List<string> MicrosoftProtocols = new()
    {
        "DCERPC", "MSRPC", "DCOM", "WMI", "BITS", "MSMQ", "ActiveDirectory"
    };

    // Industrial & IoT Protocols
    public static readonly List<string> IndustrialProtocols = new()
    {
        "Modbus", "DNP3", "IEC61850", "OPC", "OPC-UA", "PROFINET", "EtherCAT", "CAN", "MQTT", "CoAP", "AMQP"
    };

    // Wireless Protocols
    public static readonly List<string> WirelessProtocols = new()
    {
        "802.11", "WiFi", "Bluetooth", "BLE", "Zigbee", "Z-Wave", "LoRa", "NFC"
    };

    // Other Common Protocols
    public static readonly List<string> OtherProtocols = new()
    {
        "DHCP", "DHCPv6", "BOOTP", "NTP", "PTP", "VXLAN", "GTP", "Diameter", "SCCP", "ISUP",
        "Frame", "Raw", "SSDP", "UPnP", "Bonjour", "STUN", "TURN", "WebRTC"
    };

    /// <summary>
    /// Get all protocols as a single list
    /// </summary>
    public static List<string> GetAllProtocols()
    {
        var allProtocols = new List<string>();
        allProtocols.AddRange(NetworkProtocols);
        allProtocols.AddRange(TransportProtocols);
        allProtocols.AddRange(WebProtocols);
        allProtocols.AddRange(EmailProtocols);
        allProtocols.AddRange(FileTransferProtocols);
        allProtocols.AddRange(RemoteAccessProtocols);
        allProtocols.AddRange(DirectoryProtocols);
        allProtocols.AddRange(NameResolutionProtocols);
        allProtocols.AddRange(ManagementProtocols);
        allProtocols.AddRange(VoIPProtocols);
        allProtocols.AddRange(DatabaseProtocols);
        allProtocols.AddRange(SecurityProtocols);
        allProtocols.AddRange(Layer2Protocols);
        allProtocols.AddRange(RoutingProtocols);
        allProtocols.AddRange(MicrosoftProtocols);
        allProtocols.AddRange(IndustrialProtocols);
        allProtocols.AddRange(WirelessProtocols);
        allProtocols.AddRange(OtherProtocols);
        
        // Remove duplicates and sort
        var uniqueProtocols = new HashSet<string>(allProtocols, StringComparer.OrdinalIgnoreCase);
        var sortedList = new List<string>(uniqueProtocols);
        sortedList.Sort(StringComparer.OrdinalIgnoreCase);
        
        return sortedList;
    }

    /// <summary>
    /// Check if a protocol string matches any known protocol
    /// </summary>
    public static bool IsKnownProtocol(string protocolName)
    {
        if (string.IsNullOrWhiteSpace(protocolName))
            return false;
            
        var allProtocols = GetAllProtocols();
        return allProtocols.Exists(p => p.Equals(protocolName, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Map common protocol names to standard names
    /// </summary>
    public static string NormalizeProtocolName(string protocolName)
    {
        if (string.IsNullOrWhiteSpace(protocolName))
            return "Unknown";

        // Common mappings
        var mappings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "TLSv1.0", "TLSv1" },
            { "SSL3", "SSLv3" },
            { "SSL2", "SSLv2" },
            { "HTTP/2", "HTTP2" },
            { "HTTP/3", "HTTP3" },
            { "SMBv2", "SMB2" },
            { "SMBv3", "SMB3" },
            { "NetBIOS-NS", "NBNS" },
            { "NetBIOS-DGM", "NetBIOS" },
            { "NetBIOS-SSN", "NetBIOS" },
            { "MS-RPC", "MSRPC" },
            { "DCE-RPC", "DCERPC" },
            { "802.11n", "802.11" },
            { "802.11ac", "802.11" },
            { "802.11ax", "802.11" }
        };

        return mappings.TryGetValue(protocolName, out var normalized) ? normalized : protocolName;
    }
}