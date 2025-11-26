using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models.Capture;

namespace PCAPAnalyzer.Core.Services.Capture;

/// <summary>
/// Interface for live packet capture service
/// </summary>
public interface ILiveCaptureService
{
    /// <summary>
    /// Current capture session (null if no active session)
    /// </summary>
    CaptureSession? CurrentSession { get; }

    /// <summary>
    /// Event raised when a new packet is captured
    /// </summary>
    event EventHandler<LivePacketData>? PacketCaptured;

    /// <summary>
    /// Event raised when capture statistics are updated
    /// </summary>
    event EventHandler<CaptureSessionStats>? StatisticsUpdated;

    /// <summary>
    /// Event raised when capture status changes
    /// </summary>
    event EventHandler<CaptureStatus>? StatusChanged;

    /// <summary>
    /// Starts packet capture with the specified configuration
    /// </summary>
    Task<CaptureSession> StartCaptureAsync(CaptureConfiguration config, CancellationToken cancellationToken = default);

    /// <summary>
    /// Stops the current capture session
    /// </summary>
    Task StopCaptureAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Pauses the current capture session
    /// </summary>
    Task PauseCaptureAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Resumes a paused capture session
    /// </summary>
    Task ResumeCaptureAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the current capture statistics
    /// </summary>
    Task<CaptureSessionStats> GetCurrentStatisticsAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets all capture sessions (active and historical)
    /// </summary>
    Task<List<CaptureSession>> GetSessionHistoryAsync(int maxSessions = 100, CancellationToken cancellationToken = default);

    /// <summary>
    /// Exports the current capture to a file
    /// </summary>
    Task<string> ExportCaptureAsync(string outputPath, CancellationToken cancellationToken = default);

    /// <summary>
    /// Cleans up old capture files based on retention policy
    /// </summary>
    Task CleanupOldCapturesAsync(CancellationToken cancellationToken = default);
}
