using System;
using PCAPAnalyzer.Core.Capture.Models;
using PCAPAnalyzer.Core.Performance;

namespace PCAPAnalyzer.Core.Capture.Events
{
    /// <summary>
    /// Event args for packet captured event
    /// </summary>
    public sealed class PacketCapturedEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the captured packet data
        /// </summary>
        public PacketData Packet { get; init; } = null!;

        /// <summary>
        /// Gets the capture session ID
        /// </summary>
        public string SessionId { get; init; } = string.Empty;

        /// <summary>
        /// Gets the timestamp when the packet was captured
        /// </summary>
        public DateTime CaptureTimestamp { get; init; }

        /// <summary>
        /// Gets the interface on which the packet was captured
        /// </summary>
        public string InterfaceId { get; init; } = string.Empty;
    }

    /// <summary>
    /// Event args for session started event
    /// </summary>
    public sealed class SessionStartedEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the session ID
        /// </summary>
        public string SessionId { get; init; } = string.Empty;

        /// <summary>
        /// Gets the capture configuration
        /// </summary>
        public CaptureConfiguration Configuration { get; init; } = null!;

        /// <summary>
        /// Gets the timestamp when the session started
        /// </summary>
        public DateTime StartTimestamp { get; init; }

        /// <summary>
        /// Gets the network interface being captured
        /// </summary>
        public NetworkInterface Interface { get; init; } = null!;
    }

    /// <summary>
    /// Event args for session stopped event
    /// </summary>
    public sealed class SessionStoppedEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the session ID
        /// </summary>
        public string SessionId { get; init; } = string.Empty;

        /// <summary>
        /// Gets the timestamp when the session stopped
        /// </summary>
        public DateTime StopTimestamp { get; init; }

        /// <summary>
        /// Gets the reason for stopping
        /// </summary>
        public SessionStopReason Reason { get; init; }

        /// <summary>
        /// Gets the error message if session stopped due to error
        /// </summary>
        public string? ErrorMessage { get; init; }

        /// <summary>
        /// Gets the exception if session stopped due to error
        /// </summary>
        public Exception? Exception { get; init; }

        /// <summary>
        /// Gets the final capture statistics
        /// </summary>
        public CaptureStatisticsSnapshot Statistics { get; init; } = null!;

        /// <summary>
        /// Gets the duration of the capture session
        /// </summary>
        public TimeSpan Duration { get; init; }
    }

    /// <summary>
    /// Event args for statistics updated event
    /// </summary>
    public sealed class StatisticsUpdatedEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the session ID
        /// </summary>
        public string SessionId { get; init; } = string.Empty;

        /// <summary>
        /// Gets the current statistics snapshot
        /// </summary>
        public CaptureStatisticsSnapshot Statistics { get; init; } = null!;

        /// <summary>
        /// Gets the update timestamp
        /// </summary>
        public DateTime UpdateTimestamp { get; init; }
    }

    /// <summary>
    /// Event args for file rotated event
    /// </summary>
    public sealed class FileRotatedEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the session ID
        /// </summary>
        public string SessionId { get; init; } = string.Empty;

        /// <summary>
        /// Gets the old file path
        /// </summary>
        public string OldFilePath { get; init; } = string.Empty;

        /// <summary>
        /// Gets the new file path
        /// </summary>
        public string NewFilePath { get; init; } = string.Empty;

        /// <summary>
        /// Gets the rotation reason
        /// </summary>
        public RotationReason Reason { get; init; }

        /// <summary>
        /// Gets the timestamp of rotation
        /// </summary>
        public DateTime RotationTimestamp { get; init; }

        /// <summary>
        /// Gets the size of the rotated file in bytes
        /// </summary>
        public long FileSize { get; init; }

        /// <summary>
        /// Gets the number of packets in the rotated file
        /// </summary>
        public long PacketCount { get; init; }
    }

    /// <summary>
    /// Event args for capture error event
    /// </summary>
    public sealed class CaptureErrorEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the session ID
        /// </summary>
        public string SessionId { get; init; } = string.Empty;

        /// <summary>
        /// Gets the error type
        /// </summary>
        public CaptureErrorType ErrorType { get; init; }

        /// <summary>
        /// Gets the error message
        /// </summary>
        public string ErrorMessage { get; init; } = string.Empty;

        /// <summary>
        /// Gets the exception
        /// </summary>
        public Exception? Exception { get; init; }

        /// <summary>
        /// Gets the error timestamp
        /// </summary>
        public DateTime ErrorTimestamp { get; init; }

        /// <summary>
        /// Gets whether the error is recoverable
        /// </summary>
        public bool IsRecoverable { get; init; }
    }

    /// <summary>
    /// Reason for session stop
    /// </summary>
    public enum SessionStopReason
    {
        /// <summary>
        /// Session was stopped by user request
        /// </summary>
        UserRequested = 0,

        /// <summary>
        /// Session stopped due to error
        /// </summary>
        Error = 1,

        /// <summary>
        /// Session stopped due to process exit
        /// </summary>
        ProcessExited = 2,

        /// <summary>
        /// Session stopped due to timeout
        /// </summary>
        Timeout = 3,

        /// <summary>
        /// Session stopped due to resource limits
        /// </summary>
        ResourceLimit = 4
    }

    /// <summary>
    /// Reason for file rotation
    /// </summary>
    public enum RotationReason
    {
        /// <summary>
        /// File rotated due to size limit
        /// </summary>
        SizeLimit = 0,

        /// <summary>
        /// File rotated due to time limit
        /// </summary>
        TimeLimit = 1,

        /// <summary>
        /// File rotated due to user request
        /// </summary>
        UserRequested = 2,

        /// <summary>
        /// File rotated due to session stop
        /// </summary>
        SessionStopped = 3
    }

    /// <summary>
    /// Type of capture error
    /// </summary>
    public enum CaptureErrorType
    {
        /// <summary>
        /// Unknown error
        /// </summary>
        Unknown = 0,

        /// <summary>
        /// TShark process error
        /// </summary>
        ProcessError = 1,

        /// <summary>
        /// Network interface error
        /// </summary>
        InterfaceError = 2,

        /// <summary>
        /// File I/O error
        /// </summary>
        FileError = 3,

        /// <summary>
        /// Parsing error
        /// </summary>
        ParsingError = 4,

        /// <summary>
        /// Memory error
        /// </summary>
        MemoryError = 5,

        /// <summary>
        /// Permission error
        /// </summary>
        PermissionError = 6,

        /// <summary>
        /// Configuration error
        /// </summary>
        ConfigurationError = 7
    }
}
