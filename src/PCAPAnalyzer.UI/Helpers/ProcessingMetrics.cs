using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.Json;

namespace PCAPAnalyzer.UI.Helpers;

internal sealed class ProcessingMetrics
{
    private readonly List<ProcessingSample> _samples = new();
    private readonly Stopwatch _stopwatch = new();
    private readonly object _sync = new();

    private string _pcapFile = string.Empty;
    private long _expectedPackets;
    private long _peakPacketsPerSecond;
    private double _peakThroughputMbps;
    private string? _outputPath;

    private const string MetricsFolderName = "analysis";
    private const string MetricsSubFolderName = "perf";

    public void Start(string pcapFile, long expectedPackets)
    {
        lock (_sync)
        {
            _samples.Clear();
            _pcapFile = pcapFile;
            _expectedPackets = expectedPackets;
            _peakPacketsPerSecond = 0;
            _peakThroughputMbps = 0;

            var targetDir = Path.Combine(Environment.CurrentDirectory, MetricsFolderName, MetricsSubFolderName);
            Directory.CreateDirectory(targetDir);
            _outputPath = Path.Combine(targetDir, $"perf_{DateTime.Now:yyyyMMdd_HHmmss}.json");

            _stopwatch.Restart();
        }
    }

    public void Record(long packetsProcessed, long bytesProcessed, double packetsPerSecond, double throughputMbps)
    {
        lock (_sync)
        {
            if (!_stopwatch.IsRunning)
                return;

            if (packetsPerSecond > _peakPacketsPerSecond)
                _peakPacketsPerSecond = (long)packetsPerSecond;

            if (throughputMbps > _peakThroughputMbps)
                _peakThroughputMbps = throughputMbps;

            _samples.Add(new ProcessingSample
            {
                Timestamp = DateTime.UtcNow,
                PacketsProcessed = packetsProcessed,
                BytesProcessed = bytesProcessed,
                PacketsPerSecond = packetsPerSecond,
                ThroughputMbps = throughputMbps
            });
        }
    }

    public void Complete(long totalPackets, long totalBytes, long threatsDetected, double finalPacketsPerSecond)
    {
        lock (_sync)
        {
            if (!_stopwatch.IsRunning)
                return;

            _stopwatch.Stop();
            WriteSummary(totalPackets, totalBytes, threatsDetected, finalPacketsPerSecond, success: true, errorMessage: null);
        }
    }

    public void Fail(Exception ex, long packetsSoFar, long bytesSoFar)
    {
        lock (_sync)
        {
            if (!_stopwatch.IsRunning)
                return;

            _stopwatch.Stop();
            WriteSummary(packetsSoFar, bytesSoFar, threatsDetected: 0, finalPacketsPerSecond: 0, success: false, errorMessage: ex.Message);
        }
    }

    private void WriteSummary(long totalPackets, long totalBytes, long threatsDetected, double finalPacketsPerSecond, bool success, string? errorMessage)
    {
        if (string.IsNullOrWhiteSpace(_outputPath))
            return;

        var payload = new ProcessingMetricsPayload
        {
            PcapFile = _pcapFile,
            ExpectedPackets = _expectedPackets,
            TotalPackets = totalPackets,
            TotalBytes = totalBytes,
            ThreatsDetected = threatsDetected,
            DurationSeconds = _stopwatch.Elapsed.TotalSeconds,
            FinalPacketsPerSecond = finalPacketsPerSecond,
            PeakPacketsPerSecond = _peakPacketsPerSecond,
            PeakThroughputMbps = _peakThroughputMbps,
            Success = success,
            ErrorMessage = errorMessage,
            Samples = _samples
        };

        var options = new JsonSerializerOptions
        {
            WriteIndented = true
        };

        try
        {
            File.WriteAllText(_outputPath, JsonSerializer.Serialize(payload, options));
        }
        catch
        {
            // Swallow I/O errors - instrumentation should not break the analysis.
        }
    }

    private sealed class ProcessingSample
    {
        public DateTime Timestamp { get; set; }
        public long PacketsProcessed { get; set; }
        public long BytesProcessed { get; set; }
        public double PacketsPerSecond { get; set; }
        public double ThroughputMbps { get; set; }
    }

    private sealed class ProcessingMetricsPayload
    {
        public string PcapFile { get; set; } = string.Empty;
        public long ExpectedPackets { get; set; }
        public long TotalPackets { get; set; }
        public long TotalBytes { get; set; }
        public long ThreatsDetected { get; set; }
        public double DurationSeconds { get; set; }
        public double FinalPacketsPerSecond { get; set; }
        public long PeakPacketsPerSecond { get; set; }
        public double PeakThroughputMbps { get; set; }
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
        public List<ProcessingSample> Samples { get; set; } = new();
    }
}
