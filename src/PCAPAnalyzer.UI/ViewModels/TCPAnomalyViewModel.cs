using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels
{
    public partial class TCPAnomalyViewModel : ObservableObject
    {
        [ObservableProperty] private string id = string.Empty;
        [ObservableProperty] private string type = string.Empty;
        [ObservableProperty] private string description = string.Empty;
        [ObservableProperty] private string severity = string.Empty;
        [ObservableProperty] private string severityColor = "#6B7280";
        [ObservableProperty] private DateTime detectedAt;
        [ObservableProperty] private string sourceEndpoint = string.Empty;
        [ObservableProperty] private string destinationEndpoint = string.Empty;
        [ObservableProperty] private int affectedPacketCount;
        [ObservableProperty] private string tcpStream = string.Empty;
        [ObservableProperty] private string recommendation = string.Empty;
        [ObservableProperty] private Dictionary<string, object> metrics = new();

        public ICommand ViewDetailsCommand { get; }
        public Action<TCPAnomalyViewModel>? OnViewDetails { get; set; }

        public TCPAnomalyViewModel()
        {
            ViewDetailsCommand = new RelayCommand(ViewDetails);
        }

        public TCPAnomalyViewModel(TCPAnomaly anomaly) : this()
        {
            Id = anomaly.Id;
            Type = anomaly.Type.ToString();
            Description = anomaly.Description;
            Severity = anomaly.Severity.ToString();
            SeverityColor = GetSeverityColor(anomaly.Severity);
            DetectedAt = anomaly.DetectedAt;
            SourceEndpoint = $"{anomaly.SourceIP}:{anomaly.SourcePort}";
            DestinationEndpoint = $"{anomaly.DestinationIP}:{anomaly.DestinationPort}";
            AffectedPacketCount = anomaly.AffectedFrames.Count;
            TcpStream = anomaly.TCPStream;
            Recommendation = anomaly.Recommendation;
            Metrics = anomaly.Metrics;
        }

        private void ViewDetails()
        {
            OnViewDetails?.Invoke(this);
        }

        private string GetSeverityColor(AnomalySeverity severity)
        {
            return severity switch
            {
                AnomalySeverity.Critical => "#EF4444",
                AnomalySeverity.High => "#F59E0B",
                AnomalySeverity.Medium => "#3B82F6",
                AnomalySeverity.Low => "#10B981",
                _ => "#6B7280"
            };
        }
    }

    public partial class TopPortViewModel : ObservableObject
    {
        [ObservableProperty] private int port;
        [ObservableProperty] private string protocol = string.Empty;
        [ObservableProperty] private string service = string.Empty;
        [ObservableProperty] private string serviceName = string.Empty;
        [ObservableProperty] private long packetCount;
        [ObservableProperty] private string packetCountFormatted = string.Empty;
        [ObservableProperty] private long byteCount;
        [ObservableProperty] private string byteCountFormatted = string.Empty;
        [ObservableProperty] private int uniqueHostCount;
        [ObservableProperty] private double percentage;
        [ObservableProperty] private bool isWellKnown;
        [ObservableProperty] private bool isSuspicious;
        [ObservableProperty] private string displayName = string.Empty;
        [ObservableProperty] private string statusIcon = string.Empty;
        [ObservableProperty] private ObservableCollection<string> associatedIPs = new();

        public ICommand ViewDetailsCommand { get; }
        public Action<TopPortViewModel>? OnViewDetails { get; set; }

        public TopPortViewModel()
        {
            ViewDetailsCommand = new RelayCommand(ViewDetails);
        }

        public TopPortViewModel(PortAnalysis port) : this()
        {
            Port = port.Port;
            Protocol = port.Protocol;
            ServiceName = port.ServiceName;
            PacketCount = port.PacketCount;
            PacketCountFormatted = NumberFormatter.FormatCount(port.PacketCount);
            ByteCount = port.ByteCount;
            ByteCountFormatted = NumberFormatter.FormatBytes(port.ByteCount);
            UniqueHostCount = port.UniqueHosts.Count;
            Percentage = port.Percentage;
            IsWellKnown = port.IsWellKnown;
            IsSuspicious = port.IsSuspicious;
            DisplayName = $"{port.Protocol} {port.Port}";
            StatusIcon = GetStatusIcon(port);
            
            foreach (var ip in port.AssociatedIPs.Take(10))
            {
                AssociatedIPs.Add(ip);
            }
        }

        private void ViewDetails()
        {
            OnViewDetails?.Invoke(this);
        }

        private string GetStatusIcon(PortAnalysis port)
        {
            if (port.IsSuspicious) return "⚠️";
            if (port.IsWellKnown) return "✓";
            return "•";
        }
    }

    public partial class TCPStreamViewModel : ObservableObject
    {
        [ObservableProperty] private string streamId = string.Empty;
        [ObservableProperty] private string sourceEndpoint = string.Empty;
        [ObservableProperty] private string destinationEndpoint = string.Empty;
        [ObservableProperty] private long totalPackets;
        [ObservableProperty] private string totalBytesFormatted = string.Empty;
        [ObservableProperty] private double retransmissionRate;
        [ObservableProperty] private double packetLossRate;
        [ObservableProperty] private string throughputFormatted = string.Empty;
        [ObservableProperty] private string duration = string.Empty;
        [ObservableProperty] private string state = string.Empty;
        [ObservableProperty] private string stateColor = "#6B7280";
        [ObservableProperty] private int anomalyCount;
        [ObservableProperty] private ObservableCollection<TCPAnomalyViewModel> anomalies = new();

        public ICommand ViewDetailsCommand { get; }
        public Action<TCPStreamViewModel>? OnViewDetails { get; set; }

        public TCPStreamViewModel()
        {
            ViewDetailsCommand = new RelayCommand(ViewDetails);
        }

        public TCPStreamViewModel(TCPStreamAnalysis stream) : this()
        {
            StreamId = stream.StreamId;
            SourceEndpoint = stream.SourceEndpoint;
            DestinationEndpoint = stream.DestinationEndpoint;
            TotalPackets = stream.TotalPackets;
            TotalBytesFormatted = NumberFormatter.FormatBytes(stream.TotalBytes);
            RetransmissionRate = stream.RetransmissionRate;
            PacketLossRate = stream.PacketLossRate;
            ThroughputFormatted = NumberFormatter.FormatBytes((long)stream.Throughput) + "/s";
            Duration = FormatDuration(stream.EndTime - stream.StartTime);
            State = stream.State.ToString();
            StateColor = GetStateColor(stream.State);
            AnomalyCount = stream.Anomalies.Count;

            foreach (var anomaly in stream.Anomalies)
            {
                Anomalies.Add(new TCPAnomalyViewModel(anomaly));
            }
        }

        private void ViewDetails()
        {
            OnViewDetails?.Invoke(this);
        }

        private string GetStateColor(TCPConnectionState state)
        {
            return state switch
            {
                TCPConnectionState.Established => "#10B981",
                TCPConnectionState.Closed => "#EF4444",
                TCPConnectionState.Closing => "#F59E0B",
                TCPConnectionState.SynSent => "#3B82F6",
                TCPConnectionState.SynReceived => "#3B82F6",
                _ => "#6B7280"
            };
        }

        private string FormatDuration(TimeSpan duration)
        {
            return Helpers.TimeFormatter.FormatAsSeconds(duration);
        }
    }
}