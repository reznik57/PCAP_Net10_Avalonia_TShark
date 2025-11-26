using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Models
{
    public class ThreatInfo
    {
        public string Type { get; set; } = string.Empty;
        public ThreatSeverity Severity { get; set; }
        public string Description { get; set; } = string.Empty;
        public string SourceIP { get; set; } = string.Empty;
        public string DestinationIP { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public List<int> PacketNumbers { get; set; } = new();
        public double Confidence { get; set; }
        public List<string> MitigationSteps { get; set; } = new();
        public string ThreatId { get; set; } = Guid.NewGuid().ToString();
        public bool IsActive { get; set; } = true;
        public Dictionary<string, object> AdditionalData { get; set; } = new();
    }
}