using System.Collections.Frozen;
using System.Text.Json;
using PCAPAnalyzer.Core.Models;
using static PCAPAnalyzer.Core.Security.PortDatabase;

namespace PCAPAnalyzer.Core.Security;

/// <summary>
/// Loads port database from embedded JSON resource with lazy initialization.
/// Provides high-performance frozen dictionaries for port lookups.
/// </summary>
public static class PortDatabaseLoader
{
    private static readonly Lazy<FrozenDictionary<PortKey, PortInfo>> _database = new(LoadDatabase);
    private static readonly Lazy<FrozenDictionary<ushort, PortInfo>> _tcpPorts = new(BuildTcpLookup);
    private static readonly Lazy<FrozenDictionary<ushort, PortInfo>> _udpPorts = new(BuildUdpLookup);

    /// <summary>
    /// Complete port database keyed by (Port, Transport)
    /// </summary>
    public static FrozenDictionary<PortKey, PortInfo> Database => _database.Value;

    /// <summary>
    /// TCP-only port lookup for fast protocol-specific queries
    /// </summary>
    public static FrozenDictionary<ushort, PortInfo> TcpPorts => _tcpPorts.Value;

    /// <summary>
    /// UDP-only port lookup for fast protocol-specific queries
    /// </summary>
    public static FrozenDictionary<ushort, PortInfo> UdpPorts => _udpPorts.Value;

    private static FrozenDictionary<PortKey, PortInfo> LoadDatabase()
    {
        var assembly = typeof(PortDatabaseLoader).Assembly;
        using var stream = assembly.GetManifestResourceStream(
            "PCAPAnalyzer.Core.Resources.Data.ports.json")
            ?? throw new InvalidOperationException("ports.json not found as embedded resource");

        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            AllowTrailingCommas = true
        };

        var data = JsonSerializer.Deserialize<PortDataFile>(stream, options)
            ?? throw new InvalidOperationException("Failed to deserialize ports.json");

        var dict = new Dictionary<PortKey, PortInfo>(data.Ports.Count * 2); // *2 for "Both" entries

        foreach (var entry in data.Ports)
        {
            var transport = entry.Transport switch
            {
                "TCP" => PortDatabase.TransportProtocol.TCP,
                "UDP" => PortDatabase.TransportProtocol.UDP,
                "Both" => PortDatabase.TransportProtocol.Both,
                _ => throw new InvalidOperationException($"Unknown transport protocol: {entry.Transport}")
            };

            var risk = entry.Risk switch
            {
                "Low" => PortDatabase.PortRisk.Low,
                "Medium" => PortDatabase.PortRisk.Medium,
                "High" => PortDatabase.PortRisk.High,
                "Critical" => PortDatabase.PortRisk.Critical,
                "Unknown" => PortDatabase.PortRisk.Unknown,
                _ => throw new InvalidOperationException($"Unknown risk level: {entry.Risk}")
            };

            var info = new PortDatabase.PortInfo
            {
                ServiceName = entry.ServiceName,
                Description = entry.Description,
                Risk = risk,
                Category = entry.Category,
                Recommendation = entry.Recommendation
            };

            // Handle "Both" - register for TCP and UDP separately
            if (transport == PortDatabase.TransportProtocol.Both)
            {
                var tcpKey = new PortDatabase.PortKey((ushort)entry.Port, PortDatabase.TransportProtocol.TCP);
                var udpKey = new PortDatabase.PortKey((ushort)entry.Port, PortDatabase.TransportProtocol.UDP);
                dict.TryAdd(tcpKey, info);
                dict.TryAdd(udpKey, info);
            }
            else
            {
                var key = new PortDatabase.PortKey((ushort)entry.Port, transport);
                dict.TryAdd(key, info);
            }
        }

        return dict.ToFrozenDictionary();
    }

    private static FrozenDictionary<ushort, PortInfo> BuildTcpLookup()
    {
        return Database
            .Where(kvp => kvp.Key.Transport == PortDatabase.TransportProtocol.TCP)
            .ToFrozenDictionary(kvp => kvp.Key.Port, kvp => kvp.Value);
    }

    private static FrozenDictionary<ushort, PortInfo> BuildUdpLookup()
    {
        return Database
            .Where(kvp => kvp.Key.Transport == PortDatabase.TransportProtocol.UDP)
            .ToFrozenDictionary(kvp => kvp.Key.Port, kvp => kvp.Value);
    }
}
