using System;
using System.Collections.Generic;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.UI.Models;

/// <summary>
/// Event arguments for analysis completion.
/// Provides all data needed to populate tabs after FileAnalysisViewModel completes processing.
/// </summary>
public class AnalysisCompletedEventArgs : EventArgs
{
    /// <summary>
    /// Path to the analyzed PCAP file
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// Calculated network statistics (protocol distribution, bandwidth, etc.)
    /// </summary>
    public required NetworkStatistics Statistics { get; init; }

    /// <summary>
    /// All parsed packets for detailed analysis
    /// </summary>
    public required IReadOnlyList<PacketInfo> Packets { get; init; }

    /// <summary>
    /// Stage timing: How long "Reading File" stage took
    /// </summary>
    public TimeSpan ReadingDuration { get; init; }

    /// <summary>
    /// Stage timing: How long "Parsing Packets" stage took
    /// </summary>
    public TimeSpan ParsingDuration { get; init; }

    /// <summary>
    /// Stage timing: How long "Building Statistics" stage took
    /// </summary>
    public TimeSpan StatisticsDuration { get; init; }

    /// <summary>
    /// Stage timing: How long "Finalizing" stage took
    /// </summary>
    public TimeSpan FinalizingDuration { get; init; }

    /// <summary>
    /// Total analysis time (all stages combined)
    /// </summary>
    public TimeSpan TotalDuration { get; init; }

    /// <summary>
    /// File size in bytes
    /// </summary>
    public long FileSize { get; init; }

    /// <summary>
    /// Whether analysis completed successfully (vs partial/cancelled)
    /// </summary>
    public bool IsSuccessful { get; init; } = true;

    /// <summary>
    /// Optional error message if analysis failed
    /// </summary>
    public string? ErrorMessage { get; init; }
}

/// <summary>
/// Event arguments for real-time analysis progress updates.
/// Allows MainWindowViewModel to show progress indicators while FileAnalysisViewModel processes.
/// </summary>
public class AnalysisProgressEventArgs : EventArgs
{
    /// <summary>
    /// Number of packets processed so far
    /// </summary>
    public long PacketsProcessed { get; init; }

    /// <summary>
    /// Total packets expected (0 if unknown)
    /// </summary>
    public long TotalPackets { get; init; }

    /// <summary>
    /// Total bytes processed
    /// </summary>
    public long TotalBytes { get; init; }

    /// <summary>
    /// Overall progress percentage (0-100)
    /// </summary>
    public double ProgressPercentage { get; init; }

    /// <summary>
    /// Current processing stage: "Reading", "Parsing", "Statistics", "Finalizing"
    /// </summary>
    public required string CurrentStage { get; init; }

    /// <summary>
    /// Packets per second processing rate
    /// </summary>
    public long PacketsPerSecond { get; init; }

    /// <summary>
    /// Elapsed time since analysis started
    /// </summary>
    public TimeSpan ElapsedTime { get; init; }
}
