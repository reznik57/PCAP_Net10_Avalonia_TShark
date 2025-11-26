using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services;

/// <summary>
/// Compares packets between two PCAP files using content-based matching.
/// Matching key: SourceIP|DestIP|SrcPort|DstPort|Protocol|Length
/// </summary>
public class PacketComparer : IPacketComparer
{
    private readonly ILogger<PacketComparer> _logger;
    private readonly IPacketLoader _packetLoader;

    public PacketComparer(IPacketLoader packetLoader, ILogger<PacketComparer>? logger = null)
    {
        _packetLoader = packetLoader ?? throw new ArgumentNullException(nameof(packetLoader));
        _logger = logger ?? NullLogger<PacketComparer>.Instance;
    }

    public async Task<ComparisonResult> CompareAsync(
        string fileAPath,
        string fileBPath,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Starting comparison: {FileA} vs {FileB}", fileAPath, fileBPath);

        // Validate files exist
        if (!File.Exists(fileAPath))
            throw new FileNotFoundException($"File A not found: {fileAPath}");
        if (!File.Exists(fileBPath))
            throw new FileNotFoundException($"File B not found: {fileBPath}");

        progress?.Report(5);

        // Load packets from both files
        var fileAPackets = await _packetLoader.LoadPacketsAsync(fileAPath, cancellationToken);
        progress?.Report(40);
        cancellationToken.ThrowIfCancellationRequested();

        var fileBPackets = await _packetLoader.LoadPacketsAsync(fileBPath, cancellationToken);
        progress?.Report(75);
        cancellationToken.ThrowIfCancellationRequested();

        // Build lookup dictionaries by content key
        var fileAByKey = BuildPacketLookup(fileAPackets);
        var fileBByKey = BuildPacketLookup(fileBPackets);

        // Find common and unique packets
        var commonKeys = new HashSet<string>(fileAByKey.Keys);
        commonKeys.IntersectWith(fileBByKey.Keys);

        var uniqueToAKeys = new HashSet<string>(fileAByKey.Keys);
        uniqueToAKeys.ExceptWith(commonKeys);

        var uniqueToBKeys = new HashSet<string>(fileBByKey.Keys);
        uniqueToBKeys.ExceptWith(commonKeys);

        progress?.Report(85);

        // Build result list
        var allPackets = new List<ComparedPacket>();
        var fileAName = Path.GetFileName(fileAPath);
        var fileBName = Path.GetFileName(fileBPath);

        // Add common packets (use File A's version)
        foreach (var key in commonKeys)
        {
            allPackets.Add(new ComparedPacket
            {
                Packet = fileAByKey[key].First(),
                Source = PacketSource.Both,
                SourceFile = $"{fileAName} & {fileBName}"
            });
        }

        // Add unique to A
        foreach (var key in uniqueToAKeys)
        {
            foreach (var packet in fileAByKey[key])
            {
                allPackets.Add(new ComparedPacket
                {
                    Packet = packet,
                    Source = PacketSource.FileA,
                    SourceFile = fileAName
                });
            }
        }

        // Add unique to B
        foreach (var key in uniqueToBKeys)
        {
            foreach (var packet in fileBByKey[key])
            {
                allPackets.Add(new ComparedPacket
                {
                    Packet = packet,
                    Source = PacketSource.FileB,
                    SourceFile = fileBName
                });
            }
        }

        // Sort by frame number/timestamp
        allPackets = allPackets.OrderBy(p => p.Packet.Timestamp).ToList();

        progress?.Report(95);

        // Calculate protocol breakdowns for unique packets
        var protocolDiffA = fileAPackets
            .Where(p => uniqueToAKeys.Contains(GetPacketKey(p)))
            .GroupBy(p => p.GetProtocolDisplay())
            .ToDictionary(g => g.Key, g => g.Count());

        var protocolDiffB = fileBPackets
            .Where(p => uniqueToBKeys.Contains(GetPacketKey(p)))
            .GroupBy(p => p.GetProtocolDisplay())
            .ToDictionary(g => g.Key, g => g.Count());

        var statistics = new ComparisonStatistics
        {
            FileAName = fileAName,
            FileBName = fileBName,
            TotalFileA = fileAPackets.Count,
            TotalFileB = fileBPackets.Count,
            CommonCount = commonKeys.Count,
            UniqueToA = uniqueToAKeys.Count,
            UniqueToB = uniqueToBKeys.Count,
            ProtocolDiffA = protocolDiffA,
            ProtocolDiffB = protocolDiffB
        };

        progress?.Report(100);

        _logger.LogInformation(
            "Comparison complete: {Common} common, {UniqueA} unique to A, {UniqueB} unique to B",
            commonKeys.Count, uniqueToAKeys.Count, uniqueToBKeys.Count);

        return new ComparisonResult
        {
            AllPackets = allPackets,
            Statistics = statistics
        };
    }

    /// <summary>
    /// Generates a content-based key for packet matching
    /// </summary>
    private static string GetPacketKey(PacketInfo packet)
    {
        return $"{packet.SourceIP}|{packet.DestinationIP}|{packet.SourcePort}|{packet.DestinationPort}|{packet.Protocol}|{packet.Length}";
    }

    /// <summary>
    /// Builds a lookup dictionary grouping packets by their content key
    /// </summary>
    private static Dictionary<string, List<PacketInfo>> BuildPacketLookup(List<PacketInfo> packets)
    {
        var lookup = new Dictionary<string, List<PacketInfo>>();
        foreach (var packet in packets)
        {
            var key = GetPacketKey(packet);
            if (!lookup.TryGetValue(key, out var list))
            {
                list = new List<PacketInfo>();
                lookup[key] = list;
            }
            list.Add(packet);
        }
        return lookup;
    }

}
