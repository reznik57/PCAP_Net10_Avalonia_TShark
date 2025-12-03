using System;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

namespace PCAPAnalyzer.Core.Security;

/// <summary>
/// Comprehensive enterprise port database with ~600 port mappings.
/// Provides service identification and security risk assessment when L7 protocol detection unavailable.
/// Data loaded from embedded JSON via PortDatabaseLoader.
/// </summary>
public static class PortDatabase
{
    /// <summary>
    /// Risk level for a port/service
    /// </summary>
    public enum PortRisk
    {
        /// <summary>Encrypted, modern, secure protocols</summary>
        Low,
        /// <summary>Minor security concerns, may need authentication</summary>
        Medium,
        /// <summary>Plaintext credentials or notable vulnerabilities</summary>
        High,
        /// <summary>Critical vulnerabilities, deprecated protocols</summary>
        Critical,
        /// <summary>Unknown or variable risk</summary>
        Unknown
    }

    /// <summary>
    /// Port service information
    /// </summary>
    [SuppressMessage("Design", "CA1034:Nested types should not be visible",
        Justification = "PortInfo is a public data structure tightly coupled to PortDatabase API")]
    public readonly record struct PortInfo
    {
        public required string ServiceName { get; init; }
        public required string Description { get; init; }
        public required PortRisk Risk { get; init; }
        public string? Recommendation { get; init; }
        public string? Category { get; init; }
    }

    /// <summary>
    /// Lookup key combining port and transport protocol
    /// </summary>
    [SuppressMessage("Design", "CA1034:Nested types should not be visible",
        Justification = "PortKey is a public data structure tightly coupled to PortDatabase API")]
    public readonly record struct PortKey(ushort Port, TransportProtocol Transport);

    public enum TransportProtocol { TCP, UDP, Both }

    // Delegate to PortDatabaseLoader for lazy-loaded data
    private static FrozenDictionary<PortKey, PortInfo> Database => PortDatabaseLoader.Database;
    private static FrozenDictionary<ushort, PortInfo> TcpPorts => PortDatabaseLoader.TcpPorts;
    private static FrozenDictionary<ushort, PortInfo> UdpPorts => PortDatabaseLoader.UdpPorts;

    /// <summary>
    /// Look up port information by port number and transport protocol.
    /// </summary>
    public static PortInfo? GetPortInfo(ushort port, bool isTcp = true)
    {
        // Try simple lookup tables first (faster)
        if (isTcp && TcpPorts.TryGetValue(port, out var info))
            return info;
        if (!isTcp && UdpPorts.TryGetValue(port, out info))
            return info;

        return null;
    }

    /// <summary>
    /// Look up TCP port information.
    /// </summary>
    public static PortInfo? GetTcpPortInfo(ushort port) => GetPortInfo(port, true);

    /// <summary>
    /// Look up UDP port information.
    /// </summary>
    public static PortInfo? GetUdpPortInfo(ushort port) => GetPortInfo(port, false);

    /// <summary>
    /// Get the service name for a port, or null if unknown.
    /// </summary>
    public static string? GetServiceName(ushort port, bool isTcp = true)
    {
        return GetPortInfo(port, isTcp)?.ServiceName;
    }

    /// <summary>
    /// Get the risk level for a port.
    /// </summary>
    public static PortRisk GetRisk(ushort port, bool isTcp = true)
    {
        return GetPortInfo(port, isTcp)?.Risk ?? PortRisk.Unknown;
    }

    /// <summary>
    /// Check if a port is considered high-risk or critical.
    /// </summary>
    public static bool IsHighRiskPort(ushort port, bool isTcp = true)
    {
        var risk = GetRisk(port, isTcp);
        return risk == PortRisk.High || risk == PortRisk.Critical;
    }

    /// <summary>
    /// Get all ports in a specific category.
    /// </summary>
    public static IEnumerable<(ushort Port, TransportProtocol Transport, PortInfo Info)> GetPortsByCategory(string category)
    {
        foreach (var kvp in Database)
        {
            if (string.Equals(kvp.Value.Category, category, StringComparison.OrdinalIgnoreCase))
            {
                yield return (kvp.Key.Port, kvp.Key.Transport, kvp.Value);
            }
        }
    }

    /// <summary>
    /// Get all ports with a specific risk level.
    /// </summary>
    public static IEnumerable<(ushort Port, TransportProtocol Transport, PortInfo Info)> GetPortsByRisk(PortRisk risk)
    {
        foreach (var kvp in Database)
        {
            if (kvp.Value.Risk == risk)
            {
                yield return (kvp.Key.Port, kvp.Key.Transport, kvp.Value);
            }
        }
    }

    /// <summary>
    /// Get the total number of ports in the database.
    /// </summary>
    public static int Count => Database.Count;

    /// <summary>
    /// Get all available categories.
    /// </summary>
    public static IEnumerable<string> GetCategories()
    {
        return Database.Values
            .Where(v => v.Category != null)
            .Select(v => v.Category!)
            .Distinct();
    }

    /// <summary>
    /// Maps PortRisk to ProtocolSecurityEvaluator.SecurityLevel for integration.
    /// </summary>
    public static ProtocolSecurityEvaluator.SecurityLevel ToSecurityLevel(PortRisk risk)
    {
        return risk switch
        {
            PortRisk.Low => ProtocolSecurityEvaluator.SecurityLevel.Low,
            PortRisk.Medium => ProtocolSecurityEvaluator.SecurityLevel.Medium,
            PortRisk.High => ProtocolSecurityEvaluator.SecurityLevel.High,
            PortRisk.Critical => ProtocolSecurityEvaluator.SecurityLevel.Critical,
            _ => ProtocolSecurityEvaluator.SecurityLevel.Unknown
        };
    }

    /// <summary>
    /// Get color for risk level (UI display).
    /// </summary>
    public static string GetRiskColor(PortRisk risk)
    {
        return risk switch
        {
            PortRisk.Low => "#4CAF50",      // Green
            PortRisk.Medium => "#FFA726",   // Orange
            PortRisk.High => "#EF5350",     // Red
            PortRisk.Critical => "#B71C1C", // Dark Red
            _ => "#9E9E9E"                  // Gray
        };
    }
}
