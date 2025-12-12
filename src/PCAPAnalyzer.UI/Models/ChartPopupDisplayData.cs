using System;

namespace PCAPAnalyzer.UI.Models
{
    /// <summary>
    /// Anomaly data for display in the chart popup
    /// </summary>
    public class AnomalyDisplayData
    {
        public string Type { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public string SeverityColor { get; set; } = "#6B7280";
        public string Description { get; set; } = string.Empty;
        public string SourceIP { get; set; } = string.Empty;
        public string DestinationIP { get; set; } = string.Empty;
        public int AffectedFrameCount { get; set; }
        public DateTime DetectedAt { get; set; }
        public string DetectorName { get; set; } = string.Empty;
    }

    /// <summary>
    /// Threat data for display in the chart popup
    /// </summary>
    public class ThreatDisplayData
    {
        public string Type { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public string SeverityColor { get; set; } = "#6B7280";
        public string Description { get; set; } = string.Empty;
        public string SourceIP { get; set; } = string.Empty;
        public string DestinationIP { get; set; } = string.Empty;
        public double Confidence { get; set; }
        public string ConfidenceDisplay => string.Format("{0:P0}", Confidence);
        public DateTime Timestamp { get; set; }
        public int PacketCount { get; set; }
    }
}
