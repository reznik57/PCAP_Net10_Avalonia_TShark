using System;

namespace PCAPAnalyzer.Core.Models.Capture;

/// <summary>
/// Configuration for live packet capture
/// </summary>
public class CaptureConfiguration
{
    /// <summary>
    /// Interface ID to capture from
    /// </summary>
    public string InterfaceId { get; set; } = string.Empty;

    /// <summary>
    /// BPF (Berkeley Packet Filter) capture filter
    /// Examples: "tcp port 80", "host 192.168.1.1", "not port 22"
    /// </summary>
    public string CaptureFilter { get; set; } = string.Empty;

    /// <summary>
    /// Enable promiscuous mode (capture all packets on the network)
    /// </summary>
    public bool PromiscuousMode { get; set; } = true;

    /// <summary>
    /// Maximum number of bytes to capture per packet (snaplen)
    /// 0 = capture full packet, 65535 = maximum
    /// </summary>
    public int SnapshotLength { get; set; } = 65535;

    /// <summary>
    /// Read timeout in milliseconds
    /// </summary>
    public int ReadTimeoutMs { get; set; } = 1000;

    /// <summary>
    /// Buffer size in MB for packet capture
    /// </summary>
    public int BufferSizeMB { get; set; } = 50;

    /// <summary>
    /// Maximum capture duration in seconds (0 = unlimited)
    /// </summary>
    public int MaxDurationSeconds { get; set; }

    /// <summary>
    /// Maximum file size in MB for rolling captures (0 = unlimited)
    /// </summary>
    public int MaxFileSizeMB { get; set; } = 100;

    /// <summary>
    /// Auto-save interval in seconds (0 = no auto-save)
    /// </summary>
    public int AutoSaveIntervalSeconds { get; set; } = 300;

    /// <summary>
    /// Directory to save capture files
    /// </summary>
    public string OutputDirectory { get; set; } = Path.Combine(Path.GetTempPath(), "pcap_captures");

    /// <summary>
    /// File name prefix for capture files
    /// </summary>
    public string FileNamePrefix { get; set; } = "capture";

    /// <summary>
    /// Maximum number of packets to capture (0 = unlimited)
    /// </summary>
    public long MaxPackets { get; set; }

    /// <summary>
    /// Enable real-time analysis during capture
    /// </summary>
    public bool EnableRealtimeAnalysis { get; set; } = true;

    /// <summary>
    /// Number of rolling capture files to keep (0 = keep all)
    /// </summary>
    public int MaxRollingFiles { get; set; } = 10;

    /// <summary>
    /// Compress old capture files
    /// </summary>
    public bool CompressOldFiles { get; set; }

    /// <summary>
    /// Retention period in days for capture files (0 = keep forever)
    /// </summary>
    public int RetentionDays { get; set; } = 7;

    /// <summary>
    /// Validates the configuration
    /// </summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(InterfaceId))
            throw new ArgumentException("Interface ID must be specified", nameof(InterfaceId));

        if (SnapshotLength < 0 || SnapshotLength > 65535)
            throw new ArgumentOutOfRangeException(nameof(SnapshotLength), "Must be between 0 and 65535");

        if (ReadTimeoutMs < 0)
            throw new ArgumentOutOfRangeException(nameof(ReadTimeoutMs), "Must be non-negative");

        if (BufferSizeMB < 1)
            throw new ArgumentOutOfRangeException(nameof(BufferSizeMB), "Must be at least 1 MB");

        if (!Directory.Exists(OutputDirectory))
            Directory.CreateDirectory(OutputDirectory);
    }
}
