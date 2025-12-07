using System;
using System.Collections.Generic;
using PCAPAnalyzer.Core.Services;

namespace PCAPAnalyzer.Core.Models
{
    public class TCPAnomaly
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public TCPAnomalyType Type { get; set; }
        public string Description { get; set; } = string.Empty;
        public DateTime DetectedAt { get; set; }
        public string SourceIP { get; set; } = string.Empty;
        public string DestinationIP { get; set; } = string.Empty;
        public int SourcePort { get; set; }
        public int DestinationPort { get; set; }
        public AnomalySeverity Severity { get; set; }
        public List<long> AffectedFrames { get; set; } = [];
        public Dictionary<string, object> Metrics { get; set; } = [];
        public string TCPStream { get; set; } = string.Empty;
        public string Recommendation { get; set; } = string.Empty;
    }

    public enum TCPAnomalyType
    {
        Retransmission,
        PreviousSegmentNotCaptured,
        DuplicateACK,
        OutOfOrder,
        ZeroWindow,
        WindowFull,
        KeepAlive,
        KeepAliveACK,
        SpuriousRetransmission,
        FastRetransmission,
        RST,
        FIN,
        SYNFlood,
        PortScan,
        WindowScaling,
        SegmentLost,
        ACKedUnseenSegment,
        PreviousSegmentLost,
        DupACKNum,
        TCPChecksum,
        ConnectionReset,
        ConnectionTimeout
    }

    public class TCPStreamAnalysis
    {
        public string StreamId { get; set; } = string.Empty;
        public string SourceEndpoint { get; set; } = string.Empty;
        public string DestinationEndpoint { get; set; } = string.Empty;
        public long TotalPackets { get; set; }
        public long RetransmissionCount { get; set; }
        public long DuplicateACKCount { get; set; }
        public long OutOfOrderCount { get; set; }
        public long LostSegmentCount { get; set; }
        public double RetransmissionRate { get; set; }
        public double PacketLossRate { get; set; }
        public TimeSpan RoundTripTime { get; set; }
        public long TotalBytes { get; set; }
        public double Throughput { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TCPConnectionState State { get; set; }
        public List<TCPAnomaly> Anomalies { get; set; } = [];
    }

    public enum TCPConnectionState
    {
        Established,
        SynSent,
        SynReceived,
        FinWait1,
        FinWait2,
        TimeWait,
        Closed,
        CloseWait,
        LastAck,
        Listen,
        Closing,
        Unknown
    }

    public class PortAnalysis
    {
        public int Port { get; set; }
        public string Protocol { get; set; } = string.Empty; // TCP or UDP
        public string ServiceName { get; set; } = string.Empty;
        public long PacketCount { get; set; }
        public long ByteCount { get; set; }
        public HashSet<string> UniqueHosts { get; set; } = [];
        public double Percentage { get; set; }
        public bool IsWellKnown { get; set; }
        public bool IsSuspicious { get; set; }
        public List<string> AssociatedIPs { get; set; } = [];
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public Dictionary<string, long> DirectionStats { get; set; } = []; // Inbound/Outbound counts
    }

    public class TopPortsAnalysis
    {
        public List<PortAnalysis> TCPPorts { get; set; } = [];
        public List<PortAnalysis> UDPPorts { get; set; } = [];
        public List<PortAnalysis> CombinedPorts { get; set; } = [];
        public Dictionary<string, PortAnalysis> ServiceMap { get; set; } = [];
        public long TotalTCPPackets { get; set; }
        public long TotalUDPPackets { get; set; }
    }
}