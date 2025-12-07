using Microsoft.ML.Data;
using System;

namespace PCAPAnalyzer.Core.Models.ML;

/// <summary>
/// Network flow features for ML model training and prediction
/// </summary>
public class MLNetworkFlow
{
    // Flow identification
    [LoadColumn(0)]
    public string FlowId { get; set; } = string.Empty;

    // Basic flow statistics
    [LoadColumn(1)]
    public float Duration { get; set; }

    [LoadColumn(2)]
    public float TotalPackets { get; set; }

    [LoadColumn(3)]
    public float TotalBytes { get; set; }

    [LoadColumn(4)]
    public float BytesPerSecond { get; set; }

    [LoadColumn(5)]
    public float PacketsPerSecond { get; set; }

    // Packet size statistics
    [LoadColumn(6)]
    public float AvgPacketSize { get; set; }

    [LoadColumn(7)]
    public float MinPacketSize { get; set; }

    [LoadColumn(8)]
    public float MaxPacketSize { get; set; }

    [LoadColumn(9)]
    public float StdPacketSize { get; set; }

    // Temporal features
    [LoadColumn(10)]
    public float AvgInterarrivalTime { get; set; }

    [LoadColumn(11)]
    public float StdInterarrivalTime { get; set; }

    [LoadColumn(12)]
    public float HourOfDay { get; set; }

    [LoadColumn(13)]
    public float DayOfWeek { get; set; }

    // TCP-specific features
    [LoadColumn(14)]
    public float SynCount { get; set; }

    [LoadColumn(15)]
    public float AckCount { get; set; }

    [LoadColumn(16)]
    public float FinCount { get; set; }

    [LoadColumn(17)]
    public float RstCount { get; set; }

    [LoadColumn(18)]
    public float PshCount { get; set; }

    [LoadColumn(19)]
    public float RetransmissionCount { get; set; }

    // Protocol features
    [LoadColumn(20)]
    public float ProtocolType { get; set; } // Encoded: TCP=1, UDP=2, ICMP=3, etc.

    [LoadColumn(21)]
    public float SourcePort { get; set; }

    [LoadColumn(22)]
    public float DestinationPort { get; set; }

    // Direction-based features
    [LoadColumn(23)]
    public float ForwardBytes { get; set; }

    [LoadColumn(24)]
    public float BackwardBytes { get; set; }

    [LoadColumn(25)]
    public float ForwardPackets { get; set; }

    [LoadColumn(26)]
    public float BackwardPackets { get; set; }

    // Entropy features (randomness indicators)
    [LoadColumn(27)]
    public float PayloadEntropy { get; set; }

    [LoadColumn(28)]
    public float PacketSizeEntropy { get; set; }

    [LoadColumn(29)]
    public float InterarrivalEntropy { get; set; }

    // Label for supervised learning (0 = normal, 1 = anomaly)
    [LoadColumn(30)]
    public bool Label { get; set; }

    // Additional metadata (not used for training)
    public string SourceIP { get; set; } = string.Empty;
    public string DestinationIP { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
}

/// <summary>
/// Anomaly prediction result from ML model
/// </summary>
public class MLAnomalyPrediction
{
    /// <summary>
    /// Predicted label (true = anomaly, false = normal)
    /// </summary>
    [ColumnName("PredictedLabel")]
    public bool IsAnomaly { get; set; }

    /// <summary>
    /// Probability score (0.0 to 1.0, higher = more likely anomaly)
    /// </summary>
    [ColumnName("Score")]
    public float Score { get; set; }

    /// <summary>
    /// Confidence level of the prediction (0.0 to 1.0)
    /// </summary>
    public float Confidence { get; set; }

    /// <summary>
    /// Predicted anomaly category
    /// </summary>
    public string AnomalyType { get; set; } = "Unknown";

    /// <summary>
    /// Model name that produced this prediction
    /// </summary>
    public string ModelName { get; set; } = string.Empty;

    /// <summary>
    /// Feature importance scores
    /// </summary>
    public Dictionary<string, float> FeatureImportance { get; set; } = [];
}

/// <summary>
/// Ensemble prediction combining multiple models
/// </summary>
public class EnsemblePrediction
{
    public string FlowId { get; set; } = string.Empty;
    public float AggregatedScore { get; set; }
    public bool IsAnomaly { get; set; }
    public Dictionary<string, MLAnomalyPrediction> ModelPredictions { get; set; } = [];
    public string DominantAnomalyType { get; set; } = string.Empty;
    public float Confidence { get; set; }
}
