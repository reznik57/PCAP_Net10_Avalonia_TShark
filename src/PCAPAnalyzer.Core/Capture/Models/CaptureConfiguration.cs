using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Capture.Models
{
    /// <summary>
    /// Configuration for a packet capture session
    /// </summary>
    public sealed class CaptureConfiguration
    {
        /// <summary>
        /// Gets or sets the network interface to capture from
        /// </summary>
        public string InterfaceId { get; init; } = string.Empty;

        /// <summary>
        /// Gets or sets the BPF (Berkeley Packet Filter) capture filter
        /// </summary>
        public string? CaptureFilter { get; init; }

        /// <summary>
        /// Gets or sets whether to enable promiscuous mode
        /// </summary>
        public bool PromiscuousMode { get; init; } = true;

        /// <summary>
        /// Gets or sets the snapshot length (maximum bytes to capture per packet)
        /// 0 means use default (typically 65535)
        /// </summary>
        public int SnapshotLength { get; init; }

        /// <summary>
        /// Gets or sets the output file path for captured packets
        /// If null, packets are only processed in memory
        /// </summary>
        public string? OutputFilePath { get; init; }

        /// <summary>
        /// Gets or sets the output file format
        /// </summary>
        public CaptureFileFormat OutputFormat { get; init; } = CaptureFileFormat.Pcapng;

        /// <summary>
        /// Gets or sets the maximum file size in bytes before rotation (0 = unlimited)
        /// </summary>
        public long MaxFileSizeBytes { get; init; } = 100 * 1024 * 1024; // 100 MB

        /// <summary>
        /// Gets or sets the maximum duration before file rotation (0 = unlimited)
        /// </summary>
        public TimeSpan MaxFileDuration { get; init; } = TimeSpan.FromMinutes(5);

        /// <summary>
        /// Gets or sets the maximum number of rolling files to keep (0 = unlimited)
        /// </summary>
        public int MaxRollingFiles { get; init; } = 12; // 1 hour at 5-minute intervals

        /// <summary>
        /// Gets or sets whether to compress old capture files
        /// </summary>
        public bool CompressOldFiles { get; init; } = true;

        /// <summary>
        /// Gets or sets the buffer size for packet processing (in packets)
        /// </summary>
        public int BufferSize { get; init; } = 10000;

        /// <summary>
        /// Gets or sets the maximum memory limit for circular buffer (in bytes)
        /// </summary>
        public long MaxMemoryBytes { get; init; } = 512 * 1024 * 1024; // 512 MB

        /// <summary>
        /// Gets or sets whether to enable real-time statistics
        /// </summary>
        public bool EnableStatistics { get; init; } = true;

        /// <summary>
        /// Gets or sets the statistics update interval
        /// </summary>
        public TimeSpan StatisticsUpdateInterval { get; init; } = TimeSpan.FromSeconds(1);

        /// <summary>
        /// Gets or sets whether to enable live packet events
        /// </summary>
        public bool EnablePacketEvents { get; init; } = true;

        /// <summary>
        /// Gets or sets the maximum packet event rate (packets/second)
        /// 0 = unlimited
        /// </summary>
        public int MaxPacketEventRate { get; init; } = 1000;

        /// <summary>
        /// Gets or sets the TShark executable path (null to use system default)
        /// </summary>
        public string? TSharkPath { get; init; }

        /// <summary>
        /// Gets or sets additional TShark arguments
        /// </summary>
        public List<string> AdditionalTSharkArgs { get; init; } = [];

        /// <summary>
        /// Gets or sets the timeout for TShark process startup
        /// </summary>
        public TimeSpan StartupTimeout { get; init; } = TimeSpan.FromSeconds(10);

        /// <summary>
        /// Gets or sets whether to automatically restart TShark on failure
        /// </summary>
        public bool AutoRestart { get; init; } = true;

        /// <summary>
        /// Gets or sets the maximum number of restart attempts
        /// </summary>
        public int MaxRestartAttempts { get; init; } = 3;

        /// <summary>
        /// Validates the configuration
        /// </summary>
        /// <exception cref="ArgumentException">Thrown when configuration is invalid</exception>
        public void Validate()
        {
            if (string.IsNullOrWhiteSpace(InterfaceId))
            {
                throw new ArgumentException("InterfaceId must be specified", nameof(InterfaceId));
            }

            if (SnapshotLength < 0)
            {
                throw new ArgumentException("SnapshotLength must be non-negative", nameof(SnapshotLength));
            }

            if (MaxFileSizeBytes < 0)
            {
                throw new ArgumentException("MaxFileSizeBytes must be non-negative", nameof(MaxFileSizeBytes));
            }

            if (MaxFileDuration < TimeSpan.Zero)
            {
                throw new ArgumentException("MaxFileDuration must be non-negative", nameof(MaxFileDuration));
            }

            if (BufferSize <= 0)
            {
                throw new ArgumentException("BufferSize must be positive", nameof(BufferSize));
            }

            if (MaxMemoryBytes <= 0)
            {
                throw new ArgumentException("MaxMemoryBytes must be positive", nameof(MaxMemoryBytes));
            }

            if (MaxPacketEventRate < 0)
            {
                throw new ArgumentException("MaxPacketEventRate must be non-negative", nameof(MaxPacketEventRate));
            }

            if (StartupTimeout <= TimeSpan.Zero)
            {
                throw new ArgumentException("StartupTimeout must be positive", nameof(StartupTimeout));
            }

            if (MaxRestartAttempts < 0)
            {
                throw new ArgumentException("MaxRestartAttempts must be non-negative", nameof(MaxRestartAttempts));
            }
        }

        /// <summary>
        /// Creates a default configuration for the specified interface
        /// </summary>
        public static CaptureConfiguration CreateDefault(string interfaceId)
        {
            return new CaptureConfiguration
            {
                InterfaceId = interfaceId
            };
        }
    }

    /// <summary>
    /// Capture file format
    /// </summary>
    public enum CaptureFileFormat
    {
        /// <summary>
        /// Original PCAP format
        /// </summary>
        Pcap = 0,

        /// <summary>
        /// PCAP Next Generation format (recommended)
        /// </summary>
        Pcapng = 1
    }
}
