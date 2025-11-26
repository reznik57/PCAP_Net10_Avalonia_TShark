using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.TShark;

/// <summary>
/// Implementation of IPacketLoader using TSharkService.
/// Bridges the Core layer's abstraction to the TShark implementation.
/// </summary>
public class TSharkPacketLoader : IPacketLoader
{
    private readonly ILogger<TSharkPacketLoader> _logger;

    public TSharkPacketLoader(ILogger<TSharkPacketLoader>? logger = null)
    {
        _logger = logger ?? NullLogger<TSharkPacketLoader>.Instance;
    }

    public async Task<List<PacketInfo>> LoadPacketsAsync(string filePath, CancellationToken cancellationToken = default)
    {
        var packets = new List<PacketInfo>();

        await using var tshark = new TSharkService(NullLogger<TSharkService>.Instance);

        var started = await tshark.StartAnalysisAsync(filePath, cancellationToken);
        if (!started)
        {
            _logger.LogWarning("Failed to start TShark analysis for {FileName}", System.IO.Path.GetFileName(filePath));
            return packets;
        }

        await foreach (var packet in tshark.PacketReader.ReadAllAsync(cancellationToken))
        {
            packets.Add(packet);
        }

        _logger.LogDebug("Loaded {Count} packets from {FileName}", packets.Count, System.IO.Path.GetFileName(filePath));
        return packets;
    }
}
