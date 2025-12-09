using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace PCAPAnalyzer.Core.Services.GeoIP;

/// <summary>
/// Thread-safe temporary wrapper for parallel country traffic aggregation.
/// Uses ConcurrentDictionary as thread-safe HashSet (value is ignored) to avoid duplicate IP storage.
/// Fields exposed for Interlocked operations during parallel processing.
/// </summary>
[SuppressMessage("Design", "CA1051:Do not declare visible instance fields",
    Justification = "Public fields required for Interlocked operations in parallel processing")]
public sealed class TempCountryStats
{
    public string CountryCode = string.Empty;
    public long TotalPackets;
    public long OutgoingBytes;
    public long IncomingBytes;
    public long OutgoingPackets;
    public long IncomingPackets;

    // Thread-safe sets (ConcurrentDictionary as HashSet - value is ignored)
    // This prevents storing duplicate IPs during parallel aggregation
    private readonly ConcurrentDictionary<string, byte> _outgoingIPs = new();
    private readonly ConcurrentDictionary<string, byte> _incomingIPs = new();
    private readonly ConcurrentDictionary<string, byte> _uniqueIPs = new();

    /// <summary>Adds IP to outgoing set (thread-safe, no duplicates)</summary>
    public void AddOutgoingIP(string ip) => _outgoingIPs.TryAdd(ip, 0);

    /// <summary>Adds IP to incoming set (thread-safe, no duplicates)</summary>
    public void AddIncomingIP(string ip) => _incomingIPs.TryAdd(ip, 0);

    /// <summary>Adds IP to unique set (thread-safe, no duplicates)</summary>
    public void AddUniqueIP(string ip) => _uniqueIPs.TryAdd(ip, 0);

    /// <summary>Gets outgoing IPs as HashSet (for final conversion)</summary>
    public HashSet<string> GetOutgoingIPs() => new(_outgoingIPs.Keys);

    /// <summary>Gets incoming IPs as HashSet (for final conversion)</summary>
    public HashSet<string> GetIncomingIPs() => new(_incomingIPs.Keys);

    /// <summary>Gets unique IPs as HashSet (for final conversion)</summary>
    public HashSet<string> GetUniqueIPs() => new(_uniqueIPs.Keys);
}
