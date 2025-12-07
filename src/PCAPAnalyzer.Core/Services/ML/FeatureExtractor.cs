using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Models.ML;
using System;
using System.Collections.Generic;
using System.Linq;

namespace PCAPAnalyzer.Core.Services.ML;

/// <summary>
/// Extracts ML features from network packets and flows
/// </summary>
public class FeatureExtractor
{
    /// <summary>
    /// Extract features from a collection of packets (single flow)
    /// </summary>
    public MLNetworkFlow ExtractFlowFeatures(IEnumerable<PacketInfo> packets, string flowId)
    {
        var packetList = packets.ToList();
        if (packetList.Count == 0)
        {
            throw new ArgumentException("Cannot extract features from empty packet collection", nameof(packets));
        }

        var flow = new MLNetworkFlow
        {
            FlowId = flowId,
            Timestamp = packetList.First().Timestamp
        };

        // Basic statistics
        ExtractBasicStatistics(flow, packetList);

        // Packet size features
        ExtractPacketSizeFeatures(flow, packetList);

        // Temporal features
        ExtractTemporalFeatures(flow, packetList);

        // TCP-specific features
        ExtractTcpFeatures(flow, packetList);

        // Protocol features
        ExtractProtocolFeatures(flow, packetList);

        // Direction-based features
        ExtractDirectionFeatures(flow, packetList);

        // Entropy features
        ExtractEntropyFeatures(flow, packetList);

        // Metadata
        flow.SourceIP = packetList.First().SourceIP;
        flow.DestinationIP = packetList.First().DestinationIP;

        return flow;
    }

    /// <summary>
    /// Extract features from all packets grouped by flow
    /// </summary>
    public IEnumerable<MLNetworkFlow> ExtractAllFlowFeatures(IEnumerable<PacketInfo> packets)
    {
        var flows = GroupPacketsByFlow(packets);
        var results = new List<MLNetworkFlow>();

        foreach (var flow in flows)
        {
            try
            {
                var features = ExtractFlowFeatures(flow.Value, flow.Key);
                results.Add(features);
            }
            catch (Exception)
            {
                // Skip flows that cannot be processed
                continue;
            }
        }

        return results;
    }

    private void ExtractBasicStatistics(MLNetworkFlow flow, List<PacketInfo> packets)
    {
        var firstPacket = packets.First().Timestamp;
        var lastPacket = packets.Last().Timestamp;
        var duration = (lastPacket - firstPacket).TotalSeconds;

        flow.Duration = (float)Math.Max(duration, 0.001); // Avoid division by zero
        flow.TotalPackets = packets.Count;
        flow.TotalBytes = packets.Sum(p => (long)p.Length);
        flow.BytesPerSecond = flow.TotalBytes / flow.Duration;
        flow.PacketsPerSecond = flow.TotalPackets / flow.Duration;
    }

    private void ExtractPacketSizeFeatures(MLNetworkFlow flow, List<PacketInfo> packets)
    {
        var sizes = packets.Select(p => (float)p.Length).ToList();

        flow.AvgPacketSize = sizes.Average();
        flow.MinPacketSize = sizes.Min();
        flow.MaxPacketSize = sizes.Max();
        flow.StdPacketSize = CalculateStdDev(sizes);
    }

    private void ExtractTemporalFeatures(MLNetworkFlow flow, List<PacketInfo> packets)
    {
        var timestamps = packets.Select(p => p.Timestamp).OrderBy(t => t).ToList();
        var interarrivalTimes = new List<float>();

        for (int i = 1; i < timestamps.Count; i++)
        {
            var diff = (timestamps[i] - timestamps[i - 1]).TotalMilliseconds;
            interarrivalTimes.Add((float)diff);
        }

        if (interarrivalTimes.Count > 0)
        {
            flow.AvgInterarrivalTime = interarrivalTimes.Average();
            flow.StdInterarrivalTime = CalculateStdDev(interarrivalTimes);
        }

        var firstTimestamp = timestamps.First();
        flow.HourOfDay = firstTimestamp.Hour;
        flow.DayOfWeek = (float)firstTimestamp.DayOfWeek;
    }

    private void ExtractTcpFeatures(MLNetworkFlow flow, List<PacketInfo> packets)
    {
        // This is simplified - in production, you'd parse TCP flags from packet payload
        var tcpPackets = packets.Where(p => p.Protocol == Protocol.TCP).ToList();

        if (tcpPackets.Count > 0)
        {
            // Estimate based on common patterns
            flow.SynCount = tcpPackets.Count(p => p.Info?.Contains("SYN", StringComparison.OrdinalIgnoreCase) ?? false);
            flow.AckCount = tcpPackets.Count(p => p.Info?.Contains("ACK", StringComparison.OrdinalIgnoreCase) ?? false);
            flow.FinCount = tcpPackets.Count(p => p.Info?.Contains("FIN", StringComparison.OrdinalIgnoreCase) ?? false);
            flow.RstCount = tcpPackets.Count(p => p.Info?.Contains("RST", StringComparison.OrdinalIgnoreCase) ?? false);
            flow.PshCount = tcpPackets.Count(p => p.Info?.Contains("PSH", StringComparison.OrdinalIgnoreCase) ?? false);
            flow.RetransmissionCount = tcpPackets.Count(p => p.Info?.Contains("Retransmission", StringComparison.OrdinalIgnoreCase) ?? false);
        }
    }

    private void ExtractProtocolFeatures(MLNetworkFlow flow, List<PacketInfo> packets)
    {
        var firstPacket = packets.First();

        flow.ProtocolType = firstPacket.Protocol switch
        {
            Protocol.TCP => 1,
            Protocol.UDP => 2,
            Protocol.ICMP => 3,
            Protocol.HTTP => 4,
            Protocol.HTTPS => 5,
            Protocol.DNS => 6,
            _ => 0
        };

        flow.SourcePort = firstPacket.SourcePort;
        flow.DestinationPort = firstPacket.DestinationPort;
    }

    private void ExtractDirectionFeatures(MLNetworkFlow flow, List<PacketInfo> packets)
    {
        var sourceIP = packets.First().SourceIP;
        var forwardPackets = packets.Where(p => p.SourceIP == sourceIP).ToList();
        var backwardPackets = packets.Where(p => p.DestinationIP == sourceIP).ToList();

        flow.ForwardBytes = forwardPackets.Sum(p => (long)p.Length);
        flow.BackwardBytes = backwardPackets.Sum(p => (long)p.Length);
        flow.ForwardPackets = forwardPackets.Count;
        flow.BackwardPackets = backwardPackets.Count;
    }

    private void ExtractEntropyFeatures(MLNetworkFlow flow, List<PacketInfo> packets)
    {
        // Calculate Shannon entropy of payload bytes
        flow.PayloadEntropy = CalculatePayloadEntropy(packets);

        // Calculate entropy of packet sizes
        var sizes = packets.Select(p => (float)p.Length).ToList();
        flow.PacketSizeEntropy = CalculateEntropy(sizes);

        // Calculate entropy of interarrival times
        var timestamps = packets.Select(p => p.Timestamp).OrderBy(t => t).ToList();
        var interarrivalTimes = new List<float>();
        for (int i = 1; i < timestamps.Count; i++)
        {
            interarrivalTimes.Add((float)(timestamps[i] - timestamps[i - 1]).TotalMilliseconds);
        }
        flow.InterarrivalEntropy = interarrivalTimes.Count > 0 ? CalculateEntropy(interarrivalTimes) : 0;
    }

    private float CalculateStdDev(List<float> values)
    {
        if (values.Count < 2) return 0;

        var avg = values.Average();
        var sumOfSquares = values.Sum(v => (v - avg) * (v - avg));
        return (float)Math.Sqrt(sumOfSquares / values.Count);
    }

    private float CalculateEntropy(List<float> values)
    {
        if (values.Count == 0) return 0;

        var histogram = values
            .GroupBy(v => Math.Round(v, 2))
            .ToDictionary(g => g.Key, g => g.Count());

        var total = values.Count;
        var entropy = 0.0;

        foreach (var count in histogram.Values)
        {
            var probability = (double)count / total;
            if (probability > 0)
            {
                entropy -= probability * Math.Log2(probability);
            }
        }

        return (float)entropy;
    }

    private float CalculatePayloadEntropy(List<PacketInfo> packets)
    {
        var allBytes = new List<byte>();

        foreach (var packet in packets)
        {
            if (!packet.Payload.IsEmpty)
            {
                allBytes.AddRange(packet.Payload.ToArray());
            }
        }

        if (allBytes.Count == 0) return 0;

        var histogram = new int[256];
        foreach (var b in allBytes)
        {
            histogram[b]++;
        }

        var total = allBytes.Count;
        var entropy = 0.0;

        for (int i = 0; i < 256; i++)
        {
            if (histogram[i] > 0)
            {
                var probability = (double)histogram[i] / total;
                entropy -= probability * Math.Log2(probability);
            }
        }

        return (float)entropy;
    }

    private Dictionary<string, List<PacketInfo>> GroupPacketsByFlow(IEnumerable<PacketInfo> packets)
    {
        var flows = new Dictionary<string, List<PacketInfo>>();

        foreach (var packet in packets)
        {
            var flowId = GenerateFlowId(packet);

            if (!flows.ContainsKey(flowId))
            {
                flows[flowId] = new List<PacketInfo>();
            }

            flows[flowId].Add(packet);
        }

        return flows;
    }

    private string GenerateFlowId(PacketInfo packet)
    {
        // Create bidirectional flow identifier
        string[] ips = [packet.SourceIP, packet.DestinationIP];
        int[] ports = [packet.SourcePort, packet.DestinationPort];
        Array.Sort(ips);
        Array.Sort(ports);

        return $"{string.Join("-", ips)}_{string.Join("-", ports)}_{packet.Protocol}";
    }

    /// <summary>
    /// Normalize features for model input (z-score normalization)
    /// </summary>
    public void NormalizeFeatures(List<MLNetworkFlow> flows)
    {
        if (flows.Count == 0) return;

        var properties = typeof(MLNetworkFlow).GetProperties()
            .Where(p => p.PropertyType == typeof(float) && p.CanWrite);

        foreach (var prop in properties)
        {
            var values = flows.Select(f => (float)prop.GetValue(f)!).ToList();
            var mean = values.Average();
            var stdDev = CalculateStdDev(values);

            if (stdDev > 0.0001f) // Avoid division by zero
            {
                foreach (var flow in flows)
                {
                    var value = (float)prop.GetValue(flow)!;
                    var normalized = (value - mean) / stdDev;
                    prop.SetValue(flow, normalized);
                }
            }
        }
    }
}
