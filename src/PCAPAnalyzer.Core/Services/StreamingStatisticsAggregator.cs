using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services;

/// <summary>
/// Maintains rolling statistics for packet streams without retaining the full packet history.
/// Designed to feed dashboards and summaries while the underlying packet store persists full data.
/// </summary>
public sealed class StreamingStatisticsAggregator
{
    private const int MaxEndpointEntries = 5000;
    private const int MaxFlowEntries = 10000;
    private const int MaxThroughputBuckets = int.MaxValue; // Preserve full capture history for throughput analysis

    private readonly Lock _sync = new();
    private readonly Dictionary<string, ProtocolAccumulator> _protocols = [];
    private readonly Dictionary<string, EndpointAccumulator> _sources = [];
    private readonly Dictionary<string, EndpointAccumulator> _destinations = [];
    private readonly Dictionary<(string Src, string Dest, ushort SrcPort, ushort DestPort, string Protocol), FlowAccumulator> _flows = [];
    private readonly Dictionary<(ushort Port, string Protocol), PortAccumulator> _ports = [];
    private readonly Dictionary<DateTime, ThroughputAccumulator> _throughput = [];
    private readonly Queue<DateTime> _throughputOrder = [];
    private readonly HashSet<string> _uniqueIps = [];

    private long _totalPackets;
    private long _totalBytes;
    private long _threatCount;
    private DateTime? _firstPacket;
    private DateTime? _lastPacket;

    public void Reset()
    {
        lock (_sync)
        {
            _protocols.Clear();
            _sources.Clear();
            _destinations.Clear();
            _flows.Clear();
            _ports.Clear();
            _throughput.Clear();
            _throughputOrder.Clear();
            _uniqueIps.Clear();
            _totalPackets = 0;
            _totalBytes = 0;
            _threatCount = 0;
            _firstPacket = null;
            _lastPacket = null;
        }
    }

    public void AddBatch(IReadOnlyList<PacketInfo> batch)
    {
        if (batch is null || batch.Count == 0)
            return;

        lock (_sync)
        {
            foreach (var packet in batch)
            {
                UpdateTotals(packet);
                UpdateProtocols(packet);
                UpdateEndpoints(packet);
                UpdateFlows(packet);
                UpdatePorts(packet);
                UpdateThroughput(packet);

                if (IsThreateningPacket(packet))
                {
                    _threatCount++;
                }
            }

            EnforceLimits();
        }
    }

    public long GetThreatCount()
    {
        lock (_sync)
        {
            return _threatCount;
        }
    }

    public List<FlowRecord> BuildFlowRecords()
    {
        lock (_sync)
        {
            return _flows.Select(kvp => new FlowRecord
            {
                SourceIP = kvp.Key.Src,
                DestinationIP = kvp.Key.Dest,
                SourcePort = kvp.Key.SrcPort,
                DestinationPort = kvp.Key.DestPort,
                Protocol = kvp.Key.Protocol,
                PacketCount = kvp.Value.PacketCount,
                ByteCount = kvp.Value.ByteCount,
                FirstSeen = kvp.Value.FirstSeen,
                LastSeen = kvp.Value.LastSeen
            }).ToList();
        }
    }

    public NetworkStatistics BuildStatistics()
    {
        lock (_sync)
        {
            var first = _firstPacket ?? DateTime.MinValue;
            var last = _lastPacket ?? first;

            var stats = new NetworkStatistics
            {
                TotalPackets = _totalPackets,
                TotalBytes = _totalBytes,
                FirstPacketTime = first,
                LastPacketTime = last,
                StartTime = first,
                EndTime = last,
                ProtocolStats = _protocols.Values
                    .OrderByDescending(p => p.PacketCount)
                    .ToDictionary(
                        p => p.Protocol,
                        p => new ProtocolStatistics
                        {
                            Protocol = p.Protocol,
                            PacketCount = p.PacketCount,
                            ByteCount = p.ByteCount,
                            Percentage = _totalPackets > 0 ? (double)p.PacketCount / _totalPackets * 100 : 0
                        })
            };

            stats.AllUniqueIPs = new HashSet<string>(_uniqueIps);

            stats.TopSources = _sources.Values
                .OrderByDescending(e => e.PacketCount)
                .Take(30)
                .Select(e => e.ToEndpointStatistics(_totalPackets))
                .ToList();

            stats.TopDestinations = _destinations.Values
                .OrderByDescending(e => e.PacketCount)
                .Take(30)
                .Select(e => e.ToEndpointStatistics(_totalPackets))
                .ToList();

            stats.TopConversations = _flows
                .OrderByDescending(f => f.Value.PacketCount)
                .Take(30)
                .Select(f => f.Value.ToConversationStatistics(f.Key))
                .ToList();

            var totalPortOccurrences = _ports.Values.Sum(p => p.PacketCount);

            // Set total unique port count before filtering to top N
            stats.UniquePortCount = _ports.Count;

            stats.TopPorts = _ports.Values
                .OrderByDescending(p => p.PacketCount)
                .Take(30)
                .Select(p => new PortStatistics
                {
                    Port = p.Port,
                    Protocol = p.Protocol,
                    PacketCount = p.PacketCount,
                    ByteCount = p.ByteCount,
                    Percentage = totalPortOccurrences > 0 ? (double)p.PacketCount / totalPortOccurrences * 100 : 0,
                    Service = $"Port {p.Port}"
                })
                .ToList();

            stats.ThroughputTimeSeries = _throughput
                .OrderBy(t => t.Key)
                .Select(t => new TimeSeriesDataPoint
                {
                    Timestamp = t.Key,
                    Value = t.Value.Bytes,
                    PacketsPerSecond = t.Value.Packets
                })
                .ToList();

            return stats;
        }
    }

    private void UpdateTotals(PacketInfo packet)
    {
        _totalPackets++;
        _totalBytes += packet.Length;
        _uniqueIps.Add(packet.SourceIP);
        _uniqueIps.Add(packet.DestinationIP);

        if (_firstPacket is null || packet.Timestamp < _firstPacket)
            _firstPacket = packet.Timestamp;

        if (_lastPacket is null || packet.Timestamp > _lastPacket)
            _lastPacket = packet.Timestamp;
    }

    private void UpdateProtocols(PacketInfo packet)
    {
        var key = packet.Protocol.ToString();
        if (!_protocols.TryGetValue(key, out var accumulator))
        {
            accumulator = new ProtocolAccumulator(key);
            _protocols[key] = accumulator;
        }
        accumulator.Add(packet.Length);
    }

    private void UpdateEndpoints(PacketInfo packet)
    {
        if (!_sources.TryGetValue(packet.SourceIP, out var source))
        {
            source = new EndpointAccumulator(packet.SourceIP);
            _sources[packet.SourceIP] = source;
        }
        source.Add(packet.Length, packet.Protocol);

        if (!_destinations.TryGetValue(packet.DestinationIP, out var dest))
        {
            dest = new EndpointAccumulator(packet.DestinationIP);
            _destinations[packet.DestinationIP] = dest;
        }
        dest.Add(packet.Length, packet.Protocol);
    }

    private void UpdateFlows(PacketInfo packet)
    {
        var protocol = string.IsNullOrWhiteSpace(packet.L7Protocol)
            ? packet.Protocol.ToString()
            : packet.L7Protocol!;

        var key = (packet.SourceIP, packet.DestinationIP, packet.SourcePort, packet.DestinationPort, protocol);
        if (!_flows.TryGetValue(key, out var flow))
        {
            flow = new FlowAccumulator(packet.Timestamp);
            _flows[key] = flow;
        }
        flow.Add(packet.Length, packet.Timestamp);
    }

    private void UpdatePorts(PacketInfo packet)
    {
        if (packet.SourcePort > 0)
        {
            UpdatePortAccumulator(packet.SourcePort, packet.Protocol.ToString(), packet.Length);
        }

        if (packet.DestinationPort > 0)
        {
            UpdatePortAccumulator(packet.DestinationPort, packet.Protocol.ToString(), packet.Length);
        }
    }

    private void UpdatePortAccumulator(ushort port, string protocol, ushort length)
    {
        var key = (port, protocol);
        if (!_ports.TryGetValue(key, out var accumulator))
        {
            accumulator = new PortAccumulator(port, protocol);
            _ports[key] = accumulator;
        }

        accumulator.Add(length);
    }

    private void UpdateThroughput(PacketInfo packet)
    {
        var bucket = packet.Timestamp.AddMilliseconds(-packet.Timestamp.Millisecond);
        if (!_throughput.TryGetValue(bucket, out var accumulator))
        {
            accumulator = new();
            _throughput[bucket] = accumulator;
            _throughputOrder.Enqueue(bucket);
        }
        accumulator.Add(packet.Length);

        while (_throughputOrder.Count > MaxThroughputBuckets)
        {
            var oldest = _throughputOrder.Dequeue();
            _throughput.Remove(oldest);
        }
    }

    private void EnforceLimits()
    {
        if (_sources.Count > MaxEndpointEntries)
        {
            TrimDictionary(_sources, MaxEndpointEntries);
        }

        if (_destinations.Count > MaxEndpointEntries)
        {
            TrimDictionary(_destinations, MaxEndpointEntries);
        }

        if (_flows.Count > MaxFlowEntries)
        {
            TrimDictionary(_flows, MaxFlowEntries);
        }
    }

    private static void TrimDictionary<TValue>(Dictionary<string, TValue> dictionary, int maxEntries) where TValue : IAccumulator
    {
        var excess = dictionary.Count - maxEntries;
        if (excess <= 0)
            return;

        var keysToRemove = dictionary
            .OrderBy(kvp => kvp.Value.Score)
            .Take(excess)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in keysToRemove)
        {
            dictionary.Remove(key);
        }
    }

    private static void TrimDictionary<TKey>(Dictionary<TKey, FlowAccumulator> dictionary, int maxEntries) where TKey : notnull
    {
        var excess = dictionary.Count - maxEntries;
        if (excess <= 0)
            return;

        var keysToRemove = dictionary
            .OrderBy(kvp => kvp.Value.PacketCount)
            .Take(excess)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in keysToRemove)
        {
            dictionary.Remove(key);
        }
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
            var info = packet.Info!;
            return info.Contains("scan", StringComparison.OrdinalIgnoreCase) ||
                   info.Contains("attack", StringComparison.OrdinalIgnoreCase) ||
                   info.Contains("malware", StringComparison.OrdinalIgnoreCase) ||
                   info.Contains("suspicious", StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }

    private interface IAccumulator
    {
        double Score { get; }
    }

    private sealed class ProtocolAccumulator : IAccumulator
    {
        public string Protocol { get; }
        public long PacketCount { get; private set; }
        public long ByteCount { get; private set; }

        public double Score => PacketCount;

        public ProtocolAccumulator(string protocol)
        {
            Protocol = protocol;
        }

        public void Add(ushort length)
        {
            PacketCount++;
            ByteCount += length;
        }
    }

    private sealed class EndpointAccumulator : IAccumulator
    {
        private readonly Dictionary<string, long> _protocolCounts = [];

        public string Ip { get; }
        public long PacketCount { get; private set; }
        public long ByteCount { get; private set; }

        public double Score => PacketCount;

        public EndpointAccumulator(string ip)
        {
            Ip = ip;
        }

        public void Add(ushort length, Protocol protocol)
        {
            PacketCount++;
            ByteCount += length;

            var key = protocol.ToString();
            if (_protocolCounts.ContainsKey(key))
                _protocolCounts[key]++;
            else
                _protocolCounts[key] = 1;
        }

        public EndpointStatistics ToEndpointStatistics(long totalPackets)
        {
            return new EndpointStatistics
            {
                Address = Ip,
                PacketCount = PacketCount,
                ByteCount = ByteCount,
                Percentage = totalPackets > 0 ? (double)PacketCount / totalPackets * 100 : 0,
                ProtocolBreakdown = new Dictionary<string, long>(_protocolCounts)
            };
        }
    }

    private sealed class FlowAccumulator
    {
        public FlowAccumulator(DateTime timestamp)
        {
            FirstSeen = timestamp;
            LastSeen = timestamp;
        }

        public long PacketCount { get; private set; }
        public long ByteCount { get; private set; }
        public DateTime FirstSeen { get; private set; }
        public DateTime LastSeen { get; private set; }

        public void Add(ushort length, DateTime timestamp)
        {
            PacketCount++;
            ByteCount += length;
            if (timestamp < FirstSeen) FirstSeen = timestamp;
            if (timestamp > LastSeen) LastSeen = timestamp;
        }

        public ConversationStatistics ToConversationStatistics((string Src, string Dest, ushort SrcPort, ushort DestPort, string Protocol) key)
        {
            return new ConversationStatistics
            {
                SourceAddress = key.Src,
                DestinationAddress = key.Dest,
                SourcePort = key.SrcPort,
                DestinationPort = key.DestPort,
                Protocol = key.Protocol,
                PacketCount = PacketCount,
                ByteCount = ByteCount,
                StartTime = FirstSeen,
                EndTime = LastSeen
            };
        }
    }

    private sealed class ThroughputAccumulator
    {
        public long Packets { get; private set; }
        public long Bytes { get; private set; }

        public void Add(ushort length)
        {
            Packets++;
            Bytes += length;
        }
    }

    private sealed class PortAccumulator : IAccumulator
    {
        public PortAccumulator(ushort port, string protocol)
        {
            Port = port;
            Protocol = protocol;
        }

        public ushort Port { get; }
        public string Protocol { get; }
        public long PacketCount { get; private set; }
        public long ByteCount { get; private set; }

        public double Score => PacketCount;

        public void Add(ushort length)
        {
            PacketCount++;
            ByteCount += length;
        }
    }
}
