using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services;

public sealed class SimplePacketStore : IPacketStore
{
    private readonly List<PacketInfo> _packets = [];
    private readonly List<FlowRecord> _flows = [];
    private readonly Lock _sync = new();

    public Task InitializeAsync(string databasePath, CancellationToken cancellationToken = default)
    {
        // Nothing to initialize for in-memory store
        return Task.CompletedTask;
    }

    public Task InsertPacketsAsync(IEnumerable<PacketInfo> packets, CancellationToken cancellationToken = default)
    {
        if (packets == null)
            return Task.CompletedTask;

        lock (_sync)
        {
            _packets.AddRange(packets);
        }

        return Task.CompletedTask;
    }

    public Task<PacketQueryResult> QueryPacketsAsync(PacketQuery query, CancellationToken cancellationToken = default)
    {
        if (query == null)
            throw new ArgumentNullException(nameof(query));

        return Task.Run(() =>
        {
            List<PacketInfo> snapshot;
            lock (_sync)
            {
                snapshot = _packets.ToList();
            }

            IEnumerable<PacketInfo> filtered = snapshot;
            if (query.Filter != null && !query.Filter.IsEmpty)
            {
                filtered = filtered.Where(query.Filter.MatchesPacket);
            }

            List<PacketInfo> ordered;
            if (query.SortDescending)
            {
                ordered = filtered.OrderByDescending(p => p.FrameNumber).ToList();
            }
            else
            {
                ordered = filtered.OrderBy(p => p.FrameNumber).ToList();
            }

            long totalCount = 0;
            long totalBytes = 0;
            long threatCount = 0;
            DateTime? firstTimestamp = null;
            DateTime? lastTimestamp = null;

            if (query.IncludeSummary)
            {
                totalCount = ordered.Count;
                totalBytes = ordered.Sum(p => (long)p.Length);
                threatCount = ordered.Count(IsThreateningPacket);
                firstTimestamp = ordered.Count > 0 ? ordered.Min(p => p.Timestamp) : null;
                lastTimestamp = ordered.Count > 0 ? ordered.Max(p => p.Timestamp) : null;
            }

            IReadOnlyList<PacketInfo> pagePackets = Array.Empty<PacketInfo>();
            if (query.IncludePackets)
            {
                var pageSize = query.PageSize <= 0 ? 100 : query.PageSize;
                var pageNumber = query.PageNumber <= 0 ? 1 : query.PageNumber;
                var skip = Math.Max(0, (pageNumber - 1) * pageSize);
                pagePackets = ordered.Skip(skip).Take(pageSize).ToList();
            }

            return new PacketQueryResult
            {
                Packets = pagePackets,
                TotalCount = totalCount,
                TotalBytes = totalBytes,
                ThreatCount = threatCount,
                FirstPacketTimestamp = firstTimestamp,
                LastPacketTimestamp = lastTimestamp
            };
        }, cancellationToken);
    }

    public Task InsertFlowsAsync(IEnumerable<FlowRecord> flows, CancellationToken cancellationToken = default)
    {
        if (flows == null)
            return Task.CompletedTask;

        lock (_sync)
        {
            _flows.AddRange(flows);
        }

        return Task.CompletedTask;
    }

    public Task ClearAsync(CancellationToken cancellationToken = default)
    {
        lock (_sync)
        {
            _packets.Clear();
            _flows.Clear();
        }
        return Task.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        lock (_sync)
        {
            _packets.Clear();
            _flows.Clear();
        }
        return ValueTask.CompletedTask;
    }

    private static bool IsThreateningPacket(PacketInfo packet)
    {
        if (packet.Protocol == Protocol.ICMP)
            return true;

        if (packet.SourcePort == 445 || packet.DestinationPort == 445 ||
            packet.SourcePort == 139 || packet.DestinationPort == 139)
            return true;

        if (!string.IsNullOrEmpty(packet.Info))
        {
            var infoLower = packet.Info.ToLowerInvariant();
            return infoLower.Contains("scan", StringComparison.Ordinal) ||
                   infoLower.Contains("attack", StringComparison.Ordinal) ||
                   infoLower.Contains("malware", StringComparison.Ordinal) ||
                   infoLower.Contains("suspicious", StringComparison.Ordinal);
        }

        return false;
    }
}
