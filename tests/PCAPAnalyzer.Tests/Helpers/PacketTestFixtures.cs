using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Tests.Helpers;

/// <summary>
/// Pre-configured packet scenarios for common test cases
/// </summary>
public static class PacketTestFixtures
{
    /// <summary>
    /// Normal TCP traffic pattern (60% TCP, 25% UDP, 15% other)
    /// </summary>
    public static List<PacketInfo> NormalTraffic(int count = 100)
    {
        var builder = new TestDataBuilder();
        return builder.Packets
            .WithCount(count)
            .WithProtocols("TCP", "TCP", "TCP", "UDP", "UDP", "ICMP")
            .Build();
    }

    /// <summary>
    /// Port scan attack pattern (many packets to sequential ports)
    /// </summary>
    public static List<PacketInfo> PortScanAttack(string attackerIP = "10.0.0.100", string targetIP = "192.168.1.50")
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddSeconds(-10);

        for (int port = 1; port <= 1000; port++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = (uint)port,
                Timestamp = baseTime.AddMilliseconds(port * 5), // 5ms apart
                SourceIP = attackerIP,
                DestinationIP = targetIP,
                Protocol = Protocol.TCP,
                SourcePort = 54321,
                DestinationPort = (ushort)port,
                Length = 64,
                Info = $"SYN to port {port}"
            });
        }

        return packets;
    }

    /// <summary>
    /// DDoS attack pattern (many sources, one target)
    /// </summary>
    public static List<PacketInfo> DDoSAttack(int sourceCount = 100, string targetIP = "192.168.1.50")
    {
        var builder = new TestDataBuilder();
        var attackerIPs = Enumerable.Range(1, sourceCount)
            .Select(i => $"10.0.{i / 256}.{i % 256}")
            .ToArray();

        return builder.Packets
            .WithCount(sourceCount * 10)
            .WithSourceIPs(attackerIPs)
            .WithDestinationIPs(targetIP)
            .WithProtocols("UDP", "TCP", "ICMP")
            .Build();
    }

    /// <summary>
    /// DNS tunneling pattern (large DNS queries with encoded data)
    /// </summary>
    public static List<PacketInfo> DnsTunneling(string sourceIP = "192.168.1.100", int count = 20)
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddSeconds(-30);

        for (int i = 0; i < count; i++)
        {
            // Generate long subdomain (typical of DNS tunneling)
            var subdomain = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"data{i}")).Replace("=", "");

            packets.Add(new PacketInfo
            {
                FrameNumber = (uint)(i + 1),
                Timestamp = baseTime.AddSeconds(i * 2),
                SourceIP = sourceIP,
                DestinationIP = "8.8.8.8",
                Protocol = Protocol.DNS,
                SourcePort = (ushort)(53000 + i),
                DestinationPort = 53,
                Length = (ushort)(300 + subdomain.Length),
                Info = $"Query: {subdomain}.malicious-domain.com"
            });
        }

        return packets;
    }

    /// <summary>
    /// Crypto mining pattern (connections to known mining pools)
    /// </summary>
    public static List<PacketInfo> CryptoMining(string minerIP = "192.168.1.200", int poolCount = 5)
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddSeconds(-60);
        var miningPools = new[]
        {
            "pool.supportxmr.com",
            "xmr.nanopool.org",
            "mine.moneropool.com",
            "pool.minexmr.com",
            "xmr.crypto-pool.fr"
        };

        for (int i = 0; i < poolCount * 50; i++)
        {
            var pool = miningPools[i % miningPools.Length];

            packets.Add(new PacketInfo
            {
                FrameNumber = (uint)(i + 1),
                Timestamp = baseTime.AddSeconds(i * 0.5),
                SourceIP = minerIP,
                DestinationIP = $"104.{20 + i % 5}.{10 + i % 20}.{100 + i % 50}", // Varied pool IPs
                Protocol = Protocol.TCP,
                SourcePort = (ushort)(50000 + i),
                DestinationPort = (ushort)(i % 2 == 0 ? 3333 : 14444), // Common mining ports
                Length = 1200, // Large packets typical of mining
                Info = $"Mining stratum to {pool}"
            });
        }

        return packets;
    }

    /// <summary>
    /// Data exfiltration pattern (large outbound transfers)
    /// </summary>
    public static List<PacketInfo> DataExfiltration(string sourceIP = "192.168.1.50", string externalIP = "93.184.216.34")
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddSeconds(-120);

        // Large outbound transfer over 2 minutes
        for (int i = 0; i < 500; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = (uint)(i + 1),
                Timestamp = baseTime.AddMilliseconds(i * 240), // Sustained transfer
                SourceIP = sourceIP,
                DestinationIP = externalIP,
                Protocol = Protocol.HTTPS,
                SourcePort = 54321,
                DestinationPort = 443,
                Length = 1500, // Maximum packet size
                Info = $"Large outbound transfer segment {i}"
            });
        }

        return packets;
    }

    /// <summary>
    /// IoT device anomaly pattern (unusual protocol usage)
    /// </summary>
    public static List<PacketInfo> IoTAnomaly(string deviceIP = "192.168.1.150")
    {
        var builder = new TestDataBuilder();
        return builder.Packets
            .WithCount(100)
            .WithSourceIPs(deviceIP)
            .WithProtocols("MQTT", "CoAP", "HTTP", "HTTPS")
            .Build();
    }

    /// <summary>
    /// VoIP call pattern (RTP/SIP traffic)
    /// </summary>
    public static List<PacketInfo> VoIPCall(string callerIP = "192.168.1.100", string calleeIP = "192.168.1.101")
    {
        var packets = new List<PacketInfo>();
        var baseTime = DateTime.UtcNow.AddSeconds(-60);

        // SIP signaling
        packets.Add(new PacketInfo
        {
            FrameNumber = 1,
            Timestamp = baseTime,
            SourceIP = callerIP,
            DestinationIP = calleeIP,
            Protocol = Protocol.UDP,
            L7Protocol = "SIP",
            SourcePort = 5060,
            DestinationPort = 5060,
            Length = 512,
            Info = "INVITE sip:user@domain.com"
        });

        // RTP audio stream (50 pps for 1 minute)
        for (int i = 0; i < 3000; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = (uint)(i + 2),
                Timestamp = baseTime.AddMilliseconds(i * 20), // 20ms intervals
                SourceIP = callerIP,
                DestinationIP = calleeIP,
                Protocol = Protocol.UDP,
                L7Protocol = "RTP",
                SourcePort = 16384,
                DestinationPort = 16384,
                Length = 172, // Typical RTP packet size
                Info = $"RTP audio payload {i}"
            });
        }

        return packets;
    }

    /// <summary>
    /// Mixed traffic with all attack types (stress test)
    /// </summary>
    public static List<PacketInfo> MixedAttacks()
    {
        var all = new List<PacketInfo>();

        all.AddRange(NormalTraffic(500));
        all.AddRange(PortScanAttack());
        all.AddRange(DnsTunneling());
        all.AddRange(CryptoMining());
        all.AddRange(DataExfiltration());

        return all.OrderBy(p => p.Timestamp).ToList();
    }
}
