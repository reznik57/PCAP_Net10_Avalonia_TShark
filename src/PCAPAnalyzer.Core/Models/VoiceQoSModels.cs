using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Models
{
    /// <summary>
    /// Time-series data point for VoiceQoS metrics.
    /// Contains all 7 metrics (QoS count, 3x Latency, 3x Jitter) for a single time bucket.
    /// </summary>
    public class VoiceQoSTimeSeriesPoint
    {
        /// <summary>
        /// Timestamp of the start of this time bucket
        /// </summary>
        public DateTime Timestamp { get; set; }

        /// <summary>
        /// Number of QoS-marked packets in this time bucket
        /// </summary>
        public int QoSPacketCount { get; set; }

        /// <summary>
        /// Minimum latency (ms) observed across all connections in this bucket
        /// </summary>
        public double LatencyMin { get; set; }

        /// <summary>
        /// Average latency (ms) across all connections in this bucket
        /// </summary>
        public double LatencyAvg { get; set; }

        /// <summary>
        /// Maximum latency (ms) observed across all connections in this bucket
        /// </summary>
        public double LatencyMax { get; set; }

        /// <summary>
        /// 5th percentile latency (ms) - lowest 5% of latency values
        /// </summary>
        public double LatencyP5 { get; set; }

        /// <summary>
        /// 95th percentile latency (ms) - 95% of latency values are below this
        /// </summary>
        public double LatencyP95 { get; set; }

        /// <summary>
        /// Minimum jitter (ms) observed across all connections in this bucket
        /// </summary>
        public double JitterMin { get; set; }

        /// <summary>
        /// Average jitter (ms) across all connections in this bucket
        /// </summary>
        public double JitterAvg { get; set; }

        /// <summary>
        /// Maximum jitter (ms) observed across all connections in this bucket
        /// </summary>
        public double JitterMax { get; set; }

        /// <summary>
        /// 5th percentile jitter (ms) - lowest 5% of jitter values
        /// </summary>
        public double JitterP5 { get; set; }

        /// <summary>
        /// 95th percentile jitter (ms) - 95% of jitter values are below this
        /// </summary>
        public double JitterP95 { get; set; }

        /// <summary>
        /// Number of unique connections (flows) active in this time bucket
        /// </summary>
        public int ActiveConnections { get; set; }

        /// <summary>
        /// Additional metadata for debugging and analysis
        /// </summary>
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    /// <summary>
    /// Result of VoiceQoS time-series generation.
    /// Contains all time-bucketed data points and metadata about the time range.
    /// </summary>
    public class VoiceQoSTimeSeriesData
    {
        /// <summary>
        /// Ordered list of time-series data points
        /// </summary>
        public List<VoiceQoSTimeSeriesPoint> DataPoints { get; set; } = new();

        /// <summary>
        /// Start time of the first time bucket
        /// </summary>
        public DateTime StartTime { get; set; }

        /// <summary>
        /// End time of the last time bucket
        /// </summary>
        public DateTime EndTime { get; set; }

        /// <summary>
        /// Time interval/bucket size used for aggregation
        /// </summary>
        public TimeSpan Interval { get; set; }

        /// <summary>
        /// Total number of time buckets generated
        /// </summary>
        public int TotalBuckets => DataPoints?.Count ?? 0;

        /// <summary>
        /// Duration of the entire time-series
        /// </summary>
        public TimeSpan Duration => EndTime - StartTime;

        /// <summary>
        /// Total number of QoS packets across all buckets
        /// </summary>
        public int TotalQoSPackets { get; set; }

        /// <summary>
        /// Overall average latency across all buckets
        /// </summary>
        public double OverallAvgLatency { get; set; }

        /// <summary>
        /// Overall average jitter across all buckets
        /// </summary>
        public double OverallAvgJitter { get; set; }

        /// <summary>
        /// Additional statistics or metadata
        /// </summary>
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    /// <summary>
    /// Cacheable VoiceQoS analysis result including all collections
    /// </summary>
    public class VoiceQoSAnalysisResult
    {
        /// <summary>
        /// All QoS traffic items (unfiltered)
        /// </summary>
        public List<VoiceQoSTrafficItem> QoSTraffic { get; set; } = new();

        /// <summary>
        /// All high latency connections (unfiltered)
        /// </summary>
        public List<VoiceQoSLatencyItem> HighLatencyConnections { get; set; } = new();

        /// <summary>
        /// All high jitter connections (unfiltered)
        /// </summary>
        public List<VoiceQoSJitterItem> HighJitterConnections { get; set; } = new();

        /// <summary>
        /// Analysis timestamp
        /// </summary>
        public DateTime AnalysisTimestamp { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// QoS traffic item for caching (packet-less version)
    /// </summary>
    public class VoiceQoSTrafficItem
    {
        public string SourceIP { get; set; } = "";
        public string DestinationIP { get; set; } = "";
        public string Protocol { get; set; } = "";
        public int PacketCount { get; set; }
        public long TotalBytes { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public string QoSType { get; set; } = "";
        public string PortRange { get; set; } = "";
        public string DscpMarking { get; set; } = "";
        public int DscpValue { get; set; }
    }

    /// <summary>
    /// Latency connection item for caching (packet-less version)
    /// </summary>
    public class VoiceQoSLatencyItem
    {
        public string SourceIP { get; set; } = "";
        public string DestinationIP { get; set; } = "";
        public string Protocol { get; set; } = "";
        public double AverageLatency { get; set; }
        public double MaxLatency { get; set; }
        public double MinLatency { get; set; }
        public double P5Latency { get; set; } // 5th percentile
        public double P95Latency { get; set; } // 95th percentile
        public int PacketCount { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public string PortRange { get; set; } = "";
    }

    /// <summary>
    /// Jitter connection item for caching (packet-less version)
    /// </summary>
    public class VoiceQoSJitterItem
    {
        public string SourceIP { get; set; } = "";
        public string DestinationIP { get; set; } = "";
        public string Protocol { get; set; } = "";
        public double AverageJitter { get; set; }
        public double MaxJitter { get; set; }
        public double MinJitter { get; set; }
        public double P5Jitter { get; set; } // 5th percentile
        public double P95Jitter { get; set; } // 95th percentile
        public int PacketCount { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public string PortRange { get; set; } = "";
    }
}
