using System;

namespace PCAPAnalyzer.Core.Models.Capture;

/// <summary>
/// Represents an active or completed capture session
/// </summary>
public class CaptureSession
{
    /// <summary>
    /// Unique identifier for the session
    /// </summary>
    public string SessionId { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Interface being captured
    /// </summary>
    public string InterfaceName { get; set; } = string.Empty;

    /// <summary>
    /// Capture filter applied
    /// </summary>
    public string CaptureFilter { get; set; } = string.Empty;

    /// <summary>
    /// Session start time
    /// </summary>
    public DateTime StartTime { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Session end time (null if still active)
    /// </summary>
    public DateTime? EndTime { get; set; }

    /// <summary>
    /// Current session status
    /// </summary>
    public CaptureStatus Status { get; set; } = CaptureStatus.Initializing;

    /// <summary>
    /// Statistics for the current session
    /// </summary>
    public CaptureSessionStats Stats { get; set; } = new();

    /// <summary>
    /// List of capture files created during this session
    /// </summary>
    public List<string> CaptureFiles { get; set; } = new();

    /// <summary>
    /// Error message if capture failed
    /// </summary>
    public string? ErrorMessage { get; set; }

    /// <summary>
    /// Session duration
    /// </summary>
    public TimeSpan Duration => (EndTime ?? DateTime.UtcNow) - StartTime;

    /// <summary>
    /// Whether the session is currently active
    /// </summary>
    public bool IsActive => Status == CaptureStatus.Capturing || Status == CaptureStatus.Paused;
}

/// <summary>
/// Statistics for a capture session
/// </summary>
public class CaptureSessionStats
{
    /// <summary>
    /// Total packets captured
    /// </summary>
    public long TotalPackets { get; set; }

    /// <summary>
    /// Total bytes captured
    /// </summary>
    public long TotalBytes { get; set; }

    /// <summary>
    /// Packets dropped by kernel
    /// </summary>
    public long PacketsDropped { get; set; }

    /// <summary>
    /// Packets dropped by interface
    /// </summary>
    public long PacketsDroppedByInterface { get; set; }

    /// <summary>
    /// Current capture rate (packets per second)
    /// </summary>
    public double CurrentPacketsPerSecond { get; set; }

    /// <summary>
    /// Current bandwidth (bytes per second)
    /// </summary>
    public double CurrentBytesPerSecond { get; set; }

    /// <summary>
    /// Average packet size in bytes
    /// </summary>
    public double AveragePacketSize => TotalPackets > 0 ? (double)TotalBytes / TotalPackets : 0;

    /// <summary>
    /// Percentage of packets dropped
    /// </summary>
    public double DropPercentage
    {
        get
        {
            var totalProcessed = TotalPackets + PacketsDropped;
            return totalProcessed > 0 ? (double)PacketsDropped / totalProcessed * 100 : 0;
        }
    }

    /// <summary>
    /// Last statistics update time
    /// </summary>
    public DateTime LastUpdate { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Capture session status
/// </summary>
public enum CaptureStatus
{
    /// <summary>
    /// Initializing capture
    /// </summary>
    Initializing,

    /// <summary>
    /// Actively capturing packets
    /// </summary>
    Capturing,

    /// <summary>
    /// Capture paused
    /// </summary>
    Paused,

    /// <summary>
    /// Capture stopped normally
    /// </summary>
    Stopped,

    /// <summary>
    /// Capture failed with error
    /// </summary>
    Failed,

    /// <summary>
    /// Capture completed successfully
    /// </summary>
    Completed
}
