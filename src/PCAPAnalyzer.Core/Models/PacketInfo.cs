using System;
using System.Runtime.InteropServices;
using PCAPAnalyzer.Core.Security;

namespace PCAPAnalyzer.Core.Models;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public readonly record struct PacketInfo
{
    public required DateTime Timestamp { get; init; }
    public required uint FrameNumber { get; init; }
    public required ushort Length { get; init; }
    public required string SourceIP { get; init; }
    public required string DestinationIP { get; init; }
    public required ushort SourcePort { get; init; }
    public required ushort DestinationPort { get; init; }
    public required Protocol Protocol { get; init; }  // L4 Protocol (TCP/UDP)
    public string? Info { get; init; }
    public ReadOnlyMemory<byte> Payload { get; init; }

    // Layer 7 Application protocol (TLSv1.2, SNMP, DNS, etc.)
    public string? L7Protocol { get; init; }

    // TCP-specific fields for rich INFO display
    public ushort TcpFlags { get; init; }      // TCP flags bitmask (SYN=0x02, ACK=0x10, PSH=0x08, FIN=0x01, RST=0x04)
    public uint SeqNum { get; init; }          // TCP sequence number
    public uint AckNum { get; init; }          // TCP acknowledgment number
    public ushort WindowSize { get; init; }    // TCP window size

    // Credential detection flag
    public bool HasCredentials { get; init; }  // True if packet contains credential data

    // OS Fingerprinting data (nullable - only populated when packet has fingerprint signals)
    public PCAPAnalyzer.Core.Services.OsFingerprinting.OsFingerprintRawFields? OsFingerprintData { get; init; }

    // Deprecated - use L7Protocol instead
    public string? WiresharkProtocol => L7Protocol;
    
    public string GetProtocolDisplay()
    {
        // Prefer exact Wireshark protocol if available
        if (!string.IsNullOrWhiteSpace(WiresharkProtocol))
            return WiresharkProtocol;
            
        // Fall back to enum-based protocol
        return Protocol switch
        {
            Protocol.TCP => "TCP",
            Protocol.UDP => "UDP",
            Protocol.ICMP => "ICMP",
            Protocol.HTTP => "HTTP",
            Protocol.HTTPS => "HTTPS",
            Protocol.DNS => "DNS",
            Protocol.ARP => "ARP",
            Protocol.DHCP => "DHCP",
            Protocol.LLMNR => "LLMNR",
            Protocol.NBNS => "NBNS",
            _ => "Unknown"
        };
    }
    
    /// <summary>
    /// Evaluates if the protocol version is secure
    /// </summary>
    public bool IsSecureProtocol()
    {
        var assessment = ProtocolSecurityEvaluator.EvaluateProtocol(
            WiresharkProtocol ?? Protocol.ToString(), 
            SourcePort > 0 ? SourcePort : DestinationPort
        );
        return assessment.Level == ProtocolSecurityEvaluator.SecurityLevel.Secure ||
               assessment.Level == ProtocolSecurityEvaluator.SecurityLevel.Low;
    }
    
    /// <summary>
    /// Gets a security rating for the protocol
    /// </summary>
    public string GetSecurityRating()
    {
        var assessment = ProtocolSecurityEvaluator.EvaluateProtocol(
            WiresharkProtocol ?? Protocol.ToString(),
            SourcePort > 0 ? SourcePort : DestinationPort
        );
        return ProtocolSecurityEvaluator.GetSecurityLevelString(assessment.Level);
    }
    
    /// <summary>
    /// Gets detailed security assessment for the protocol
    /// </summary>
    public ProtocolSecurityEvaluator.SecurityAssessment GetSecurityAssessment()
    {
        return ProtocolSecurityEvaluator.EvaluateProtocol(
            WiresharkProtocol ?? Protocol.ToString(),
            SourcePort > 0 ? SourcePort : DestinationPort
        );
    }

    /// <summary>
    /// Builds a rich INFO string with TCP state labels and details
    /// Returns original Info if not TCP or if TCP fields are empty
    /// </summary>
    public string GetEnrichedInfo()
    {
        // Return original Info if not TCP protocol
        if (Protocol != Protocol.TCP)
            return Info ?? string.Empty;

        // Return original Info if no TCP flags set (not a TCP packet)
        if (TcpFlags == 0)
            return Info ?? string.Empty;

        // Build TCP state label: [SYN], [PSH, ACK], [FIN, ACK], etc.
        var flags = new System.Collections.Generic.List<string>();
        if ((TcpFlags & 0x02) != 0) flags.Add("SYN");
        if ((TcpFlags & 0x01) != 0) flags.Add("FIN");
        if ((TcpFlags & 0x04) != 0) flags.Add("RST");
        if ((TcpFlags & 0x08) != 0) flags.Add("PSH");
        if ((TcpFlags & 0x10) != 0) flags.Add("ACK");
        if ((TcpFlags & 0x20) != 0) flags.Add("URG");

        var stateLabel = flags.Count > 0 ? $"[{string.Join(", ", flags)}]" : "";

        // Build sequence/ack details
        var details = new System.Collections.Generic.List<string>();
        if (SeqNum > 0) details.Add($"Seq={SeqNum}");
        if (AckNum > 0 && (TcpFlags & 0x10) != 0) details.Add($"Ack={AckNum}");
        if (WindowSize > 0) details.Add($"Win={WindowSize}");
        details.Add($"Len={Length}");

        // ✅ FIX: TShark already provides enriched TCP info with flags
        // Just return the original Info from TShark - don't duplicate TCP flags
        if (!string.IsNullOrWhiteSpace(Info))
            return Info;

        // Fallback: Build enriched info if TShark didn't provide it
        var enriched = stateLabel.Length > 0
            ? $"{stateLabel} {string.Join(" ", details)}"
            : string.Join(" ", details);

        return enriched;
    }
}

public enum Protocol
{
    Unknown = 0,
    TCP = 6,
    UDP = 17,
    ICMP = 1,
    HTTP = 80,
    HTTPS = 443,
    DNS = 53,
    ARP = 254,
    DHCP = 67,
    LLMNR = 5355,  // Link-Local Multicast Name Resolution
    NBNS = 137      // NetBIOS Name Service
}

public class PacketStatistics
{
    public long TotalPackets { get; set; }
    public long TotalBytes { get; set; }
    public DateTime FirstPacketTime { get; set; }
    public DateTime LastPacketTime { get; set; }
    public Dictionary<Protocol, long> ProtocolCounts { get; set; } = new();
    public Dictionary<string, long> TopTalkers { get; set; } = new();
    public double PacketsPerSecond { get; set; }
    public double BytesPerSecond { get; set; }
}