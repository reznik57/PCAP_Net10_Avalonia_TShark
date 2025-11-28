using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services;

/// <summary>
/// Lightweight packet store that keeps all packets in memory for maximum ingest throughput.
/// Trades persistence for speed and relies on ample RAM.
/// </summary>
public sealed class InMemoryPacketStore : IPacketStore
{
    private readonly List<PacketInfo> _packets = new();
    private readonly List<FlowRecord> _flows = new();
    private readonly ReaderWriterLockSlim _lock = new(LockRecursionPolicy.NoRecursion);

    private long _totalBytes;
    private long _threatCount;
    private DateTime? _firstPacket;
    private DateTime? _lastPacket;

    public Task InitializeAsync(string databasePath, CancellationToken cancellationToken = default)
    {
        _lock.EnterWriteLock();
        try
        {
            _packets.Clear();
            _flows.Clear();
            _totalBytes = 0;
            _threatCount = 0;
            _firstPacket = null;
            _lastPacket = null;
        }
        finally
        {
            _lock.ExitWriteLock();
        }

        return Task.CompletedTask;
    }

    public Task InsertPacketsAsync(IEnumerable<PacketInfo> packets, CancellationToken cancellationToken = default)
    {
        if (packets == null)
            return Task.CompletedTask;

        // Materialize once outside of the lock to avoid holding the lock while enumerating.
        var materialized = packets as IList<PacketInfo> ?? packets.ToList();
        if (materialized.Count == 0)
            return Task.CompletedTask;

        _lock.EnterWriteLock();
        try
        {
            _packets.AddRange(materialized);

            foreach (var packet in materialized)
            {
                _totalBytes += packet.Length;
                if (!IsTimestampKnown(_firstPacket) || packet.Timestamp < _firstPacket)
                {
                    _firstPacket = packet.Timestamp;
                }

                if (!IsTimestampKnown(_lastPacket) || packet.Timestamp > _lastPacket)
                {
                    _lastPacket = packet.Timestamp;
                }

                if (IsThreateningPacket(packet))
                {
                    _threatCount++;
                }
            }
        }
        finally
        {
            _lock.ExitWriteLock();
        }

        return Task.CompletedTask;
    }

    public Task<PacketQueryResult> QueryPacketsAsync(PacketQuery query, CancellationToken cancellationToken = default)
    {
        if (query == null)
            throw new ArgumentNullException(nameof(query));

        _lock.EnterReadLock();
        try
        {
            var filter = query.Filter;
            var hasFilter = filter != null && !filter.IsEmpty;

            IList<PacketInfo> workingSet = hasFilter
                ? _packets.Where(p => filter!.MatchesPacket(p)).ToList()
                : (IList<PacketInfo>)_packets;

            long totalCount = query.IncludeSummary ? workingSet.Count : 0;
            long totalBytes = 0;
            long threatCount = 0;
            DateTime? firstTimestamp = null;
            DateTime? lastTimestamp = null;

            if (query.IncludeSummary)
            {
                if (!hasFilter)
                {
                    totalBytes = _totalBytes;
                    threatCount = _threatCount;
                    firstTimestamp = _firstPacket;
                    lastTimestamp = _lastPacket;
                }
                else if (workingSet.Count > 0)
                {
                    foreach (var packet in workingSet)
                    {
                        totalBytes += packet.Length;
                        if (!firstTimestamp.HasValue || packet.Timestamp < firstTimestamp)
                            firstTimestamp = packet.Timestamp;
                        if (!lastTimestamp.HasValue || packet.Timestamp > lastTimestamp)
                            lastTimestamp = packet.Timestamp;
                        if (IsThreateningPacket(packet))
                            threatCount++;
                    }
                }
            }

            IReadOnlyList<PacketInfo> pagePackets = Array.Empty<PacketInfo>();
            if (query.IncludePackets && workingSet.Count > 0)
            {
                var page = ExtractPage(workingSet, query.PageNumber, query.PageSize, query.SortDescending);
                pagePackets = page;
            }

            return Task.FromResult(new PacketQueryResult
            {
                Packets = pagePackets,
                TotalCount = totalCount,
                TotalBytes = totalBytes,
                ThreatCount = threatCount,
                FirstPacketTimestamp = firstTimestamp,
                LastPacketTimestamp = lastTimestamp
            });
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    public Task InsertFlowsAsync(IEnumerable<FlowRecord> flows, CancellationToken cancellationToken = default)
    {
        if (flows == null)
            return Task.CompletedTask;

        var materialized = flows as IList<FlowRecord> ?? flows.ToList();

        _lock.EnterWriteLock();
        try
        {
            _flows.Clear();
            _flows.AddRange(materialized);
        }
        finally
        {
            _lock.ExitWriteLock();
        }

        return Task.CompletedTask;
    }

    public Task ClearAsync(CancellationToken cancellationToken = default)
    {
        _lock.EnterWriteLock();
        try
        {
            _packets.Clear();
            _flows.Clear();
            _totalBytes = 0;
            _threatCount = 0;
            _firstPacket = null;
            _lastPacket = null;
        }
        finally
        {
            _lock.ExitWriteLock();
        }

        return Task.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        _lock.Dispose();
        return ValueTask.CompletedTask;
    }

    private static bool IsTimestampKnown(DateTime? timestamp) => timestamp.HasValue && timestamp.Value != default;

    private static bool IsThreateningPacket(PacketInfo packet)
    {
        if (packet.Protocol == Protocol.ICMP)
            return true;

        if (packet.SourcePort == 445 || packet.DestinationPort == 445 ||
            packet.SourcePort == 139 || packet.DestinationPort == 139)
            return true;

        if (!string.IsNullOrEmpty(packet.Info))
        {
            return packet.Info.Contains("scan", StringComparison.OrdinalIgnoreCase) ||
                   packet.Info.Contains("attack", StringComparison.OrdinalIgnoreCase) ||
                   packet.Info.Contains("malware", StringComparison.OrdinalIgnoreCase) ||
                   packet.Info.Contains("suspicious", StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }

    private static IReadOnlyList<PacketInfo> ExtractPage(IList<PacketInfo> packets, int pageNumber, int pageSize, bool sortDescending)
    {
        if (packets.Count == 0)
            return Array.Empty<PacketInfo>();

        pageNumber = Math.Max(1, pageNumber);
        pageSize = Math.Max(1, pageSize); // No upper limit - let caller decide page size

        var totalCount = packets.Count;
        if (!sortDescending)
        {
            var startIndex = Math.Min((pageNumber - 1) * pageSize, Math.Max(0, totalCount - 1));
            var remaining = Math.Max(0, totalCount - startIndex);
            var take = Math.Min(pageSize, remaining);
            if (take == 0)
                return Array.Empty<PacketInfo>();

            var result = new List<PacketInfo>(take);
            for (var i = 0; i < take; i++)
            {
                result.Add(packets[startIndex + i]);
            }
            return result;
        }
        else
        {
            // Descending: newest packets first (end of list)
            var startOffset = (pageNumber - 1) * pageSize;
            if (startOffset >= totalCount)
                return Array.Empty<PacketInfo>();

            var endIndexExclusive = totalCount - startOffset;
            var startIndex = Math.Max(0, endIndexExclusive - pageSize);
            var result = new List<PacketInfo>(endIndexExclusive - startIndex);
            for (var i = endIndexExclusive - 1; i >= startIndex; i--)
            {
                result.Add(packets[i]);
            }
            return result;
        }
    }
}
