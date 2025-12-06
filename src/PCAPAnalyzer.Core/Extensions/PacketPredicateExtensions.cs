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
}
