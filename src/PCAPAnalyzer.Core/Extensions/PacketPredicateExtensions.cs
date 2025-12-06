using System;
using System.Linq;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Extensions;

/// <summary>
/// C# 14-ready extension methods for PacketInfo anomaly detection predicates.
/// Makes filtering chains more readable and IntelliSense-discoverable.
/// </summary>
public static class PacketPredicateExtensions
{
    #region Malformed Packet Detection

    private static readonly string[] MalformedIndicators =
    [
        "[Malformed",
        "Bad ",
        "Invalid ",
        "[Truncated]",
        "[Reassembly error"
    ];

    /// <summary>
    /// Checks if packet contains malformed/invalid indicators from TShark parsing.
    /// </summary>
    public static bool IsMalformed(this PacketInfo packet) =>
        packet.Info is { } info &&
        MalformedIndicators.Any(indicator =>
            info.Contains(indicator, StringComparison.OrdinalIgnoreCase));

    #endregion

    #region Cryptocurrency Mining Detection

    private static readonly string[] CryptoMiningIndicators =
    [
        "mining.subscribe",
        "mining.authorize",
        "mining.submit",
        "mining.notify",
        "stratum+tcp",
        "stratum+ssl",
        "\"method\":\"mining"
    ];

    private static readonly string[] MiningPoolPatterns =
    [
        "pool", "mining", "nicehash", "ethermine", "f2pool", "antpool",
        "slushpool", "viaBTC", "btc.com", "poolin", "nanopool", "sparkpool",
        "2miners", "hiveon", "ezil", "flexpool", "herominers", "moneroocean",
        "supportxmr", "minexmr", "xmrpool", "hashvault", "miningpoolhub"
    ];

    /// <summary>
    /// Checks if packet contains Stratum mining protocol indicators.
    /// </summary>
    public static bool IsStratumProtocol(this PacketInfo packet) =>
        packet.Info is { } info &&
        CryptoMiningIndicators.Any(indicator =>
            info.Contains(indicator, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Checks if packet destination matches known mining pool patterns.
    /// </summary>
    public static bool IsMiningPoolDestination(this PacketInfo packet) =>
        !string.IsNullOrEmpty(packet.DestinationIP) &&
        MiningPoolPatterns.Any(pattern =>
            packet.DestinationIP.Contains(pattern, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Checks if packet info contains mining pool keywords.
    /// </summary>
    public static bool HasMiningPoolKeywords(this PacketInfo packet) =>
        packet.Info is { } info &&
        MiningPoolPatterns.Any(pattern =>
            info.Contains(pattern, StringComparison.OrdinalIgnoreCase));

    #endregion

    #region DNS Anomaly Detection

    private static readonly string[] KnownTxtQueryPatterns =
    [
        "_dmarc", "_spf", "google", "microsoft", "cloudflare",
        "_domainkey", "_acme-challenge"
    ];

    /// <summary>
    /// Checks if packet is DNS traffic (by protocol or port).
    /// </summary>
    public static bool IsDnsTraffic(this PacketInfo packet) =>
        packet.Protocol == Protocol.DNS ||
        packet.DestinationPort == 53 ||
        packet.SourcePort == 53;

    /// <summary>
    /// Checks if DNS TXT query is for a known legitimate purpose.
    /// </summary>
    public static bool IsKnownTxtQuery(this PacketInfo packet) =>
        packet.Info is { } info &&
        KnownTxtQueryPatterns.Any(pattern =>
            info.Contains(pattern, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Checks if DNS query contains TXT record request.
    /// </summary>
    public static bool IsTxtQuery(this PacketInfo packet) =>
        packet.Info?.Contains("TXT", StringComparison.OrdinalIgnoreCase) == true;

    #endregion

    #region Traffic Classification

    /// <summary>
    /// Checks if packet exceeds byte threshold (potential large transfer).
    /// </summary>
    public static bool IsLargeTransfer(this PacketInfo packet, int thresholdBytes = 10_000) =>
        packet.Length > thresholdBytes;

    /// <summary>
    /// Checks if packet is TCP protocol.
    /// </summary>
    public static bool IsTcp(this PacketInfo packet) =>
        packet.Protocol == Protocol.TCP;

    /// <summary>
    /// Checks if packet is UDP protocol.
    /// </summary>
    public static bool IsUdp(this PacketInfo packet) =>
        packet.Protocol == Protocol.UDP;

    /// <summary>
    /// Checks if packet uses a specific destination port.
    /// </summary>
    public static bool ToPort(this PacketInfo packet, int port) =>
        packet.DestinationPort == port;

    /// <summary>
    /// Checks if packet uses any of the specified destination ports.
    /// </summary>
    public static bool ToAnyPort(this PacketInfo packet, params int[] ports) =>
        ports.Contains(packet.DestinationPort);

    /// <summary>
    /// Checks if packet originates from any of the specified source ports.
    /// </summary>
    public static bool FromAnyPort(this PacketInfo packet, params int[] ports) =>
        ports.Contains(packet.SourcePort);

    #endregion

    #region Security Indicators

    /// <summary>
    /// Checks if packet contains credential-related data.
    /// </summary>
    public static bool ContainsCredentials(this PacketInfo packet) =>
        packet.HasCredentials;

    /// <summary>
    /// Checks if packet uses an insecure (cleartext) protocol.
    /// </summary>
    public static bool IsInsecureProtocol(this PacketInfo packet) =>
        !packet.IsSecureProtocol();

    #endregion

    #region TCP Anomaly Detection

    /// <summary>
    /// Checks if packet is a TCP retransmission.
    /// </summary>
    public static bool IsTcpRetransmission(this PacketInfo packet) =>
        packet.Info?.Contains("TCP Retransmission", StringComparison.OrdinalIgnoreCase) == true ||
        packet.Info?.Contains("[TCP Retransmission]", StringComparison.OrdinalIgnoreCase) == true;

    /// <summary>
    /// Checks if packet is a TCP duplicate ACK.
    /// </summary>
    public static bool IsTcpDuplicateAck(this PacketInfo packet) =>
        packet.Info?.Contains("Dup ACK", StringComparison.OrdinalIgnoreCase) == true ||
        packet.Info?.Contains("[TCP Dup ACK", StringComparison.OrdinalIgnoreCase) == true;

    /// <summary>
    /// Checks if packet is TCP out-of-order.
    /// </summary>
    public static bool IsTcpOutOfOrder(this PacketInfo packet) =>
        packet.Info?.Contains("Out-Of-Order", StringComparison.OrdinalIgnoreCase) == true ||
        packet.Info?.Contains("[TCP Out-Of-Order]", StringComparison.OrdinalIgnoreCase) == true;

    /// <summary>
    /// Checks if packet has TCP zero window.
    /// </summary>
    public static bool IsTcpZeroWindow(this PacketInfo packet) =>
        packet.Info?.Contains("Win=0", StringComparison.OrdinalIgnoreCase) == true ||
        packet.Info?.Contains("[TCP ZeroWindow]", StringComparison.OrdinalIgnoreCase) == true;

    /// <summary>
    /// Checks if packet is a SYN packet (without ACK).
    /// </summary>
    public static bool IsSynPacket(this PacketInfo packet) =>
        packet.Info?.Contains("SYN", StringComparison.OrdinalIgnoreCase) == true &&
        packet.Info?.Contains("ACK", StringComparison.OrdinalIgnoreCase) != true;

    /// <summary>
    /// Checks if packet is a SYN-ACK packet.
    /// </summary>
    public static bool IsSynAckPacket(this PacketInfo packet) =>
        packet.Info?.Contains("SYN, ACK", StringComparison.OrdinalIgnoreCase) == true;

    #endregion

    #region Protocol-Specific Detection

    /// <summary>
    /// Checks if packet is ARP protocol.
    /// </summary>
    public static bool IsArp(this PacketInfo packet) =>
        packet.Protocol == Protocol.ARP;

    /// <summary>
    /// Checks if packet is ICMP protocol.
    /// </summary>
    public static bool IsIcmp(this PacketInfo packet) =>
        packet.Protocol == Protocol.ICMP;

    /// <summary>
    /// Checks if packet is an ARP reply ("is at" pattern).
    /// </summary>
    public static bool IsArpReply(this PacketInfo packet) =>
        packet.Protocol == Protocol.ARP &&
        packet.Info?.Contains("is at", StringComparison.OrdinalIgnoreCase) == true;

    /// <summary>
    /// Checks if packet is SIP traffic.
    /// </summary>
    public static bool IsSipTraffic(this PacketInfo packet) =>
        packet.DestinationPort == 5060 ||
        packet.SourcePort == 5060 ||
        packet.Info?.Contains("SIP", StringComparison.OrdinalIgnoreCase) == true ||
        packet.L7Protocol?.Contains("SIP", StringComparison.OrdinalIgnoreCase) == true;

    /// <summary>
    /// Checks if packet is RTP traffic (UDP in common RTP port range).
    /// </summary>
    public static bool IsRtpTraffic(this PacketInfo packet) =>
        packet.Protocol == Protocol.UDP &&
        ((packet.DestinationPort >= 10000 && packet.DestinationPort <= 20000) ||
         (packet.SourcePort >= 10000 && packet.SourcePort <= 20000));

    /// <summary>
    /// Checks if packet is MQTT traffic.
    /// </summary>
    public static bool IsMqttTraffic(this PacketInfo packet) =>
        packet.DestinationPort == 1883 ||
        packet.SourcePort == 1883 ||
        packet.DestinationPort == 8883 ||
        packet.SourcePort == 8883 ||
        packet.Info?.Contains("MQTT", StringComparison.OrdinalIgnoreCase) == true;

    /// <summary>
    /// Checks if packet is CoAP traffic.
    /// </summary>
    public static bool IsCoapTraffic(this PacketInfo packet) =>
        packet.DestinationPort == 5683 ||
        packet.SourcePort == 5683 ||
        packet.DestinationPort == 5684 ||
        packet.SourcePort == 5684 ||
        packet.Info?.Contains("CoAP", StringComparison.OrdinalIgnoreCase) == true;

    /// <summary>
    /// Checks if packet is IoT traffic (MQTT or CoAP).
    /// </summary>
    public static bool IsIoTTraffic(this PacketInfo packet) =>
        packet.IsMqttTraffic() || packet.IsCoapTraffic();

    #endregion

    #region SIP Method Detection

    /// <summary>
    /// Checks if packet is a SIP INVITE.
    /// </summary>
    public static bool IsSipInvite(this PacketInfo packet) =>
        packet.Info?.Contains("INVITE", StringComparison.OrdinalIgnoreCase) == true;

    /// <summary>
    /// Checks if packet is a SIP REGISTER.
    /// </summary>
    public static bool IsSipRegister(this PacketInfo packet) =>
        packet.Info?.Contains("REGISTER", StringComparison.OrdinalIgnoreCase) == true;

    /// <summary>
    /// Checks if packet is a SIP 200 OK response.
    /// </summary>
    public static bool IsSip200Ok(this PacketInfo packet) =>
        packet.Info?.Contains("200 OK", StringComparison.OrdinalIgnoreCase) == true;

    #endregion

    #region Data Exfiltration Detection

    /// <summary>
    /// Checks if packet info contains base64 or encoding indicators.
    /// </summary>
    public static bool HasEncodingIndicators(this PacketInfo packet) =>
        packet.Info?.Contains("base64", StringComparison.OrdinalIgnoreCase) == true ||
        packet.Info?.Contains("encoding", StringComparison.OrdinalIgnoreCase) == true;

    #endregion
}
