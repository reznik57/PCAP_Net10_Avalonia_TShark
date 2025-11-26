using System;
using System.Globalization;
using System.Threading;

namespace PCAPAnalyzer.Core.Capture.Models
{
    /// <summary>
    /// Real-time statistics for packet capture session
    /// </summary>
    public sealed class CaptureStatistics
    {
        private long _packetsCaptured;
        private long _packetsDropped;
        private long _packetsReceived;
        private long _bytesReceived;
        private long _packetsProcessed;
        private long _processingErrors;
        private readonly DateTime _startTime;

        /// <summary>
        /// Gets the total number of packets captured
        /// </summary>
        public long PacketsCaptured => Interlocked.Read(ref _packetsCaptured);

        /// <summary>
        /// Gets the total number of packets dropped by the capture system
        /// </summary>
        public long PacketsDropped => Interlocked.Read(ref _packetsDropped);

        /// <summary>
        /// Gets the total number of packets received from network
        /// </summary>
        public long PacketsReceived => Interlocked.Read(ref _packetsReceived);

        /// <summary>
        /// Gets the total bytes received
        /// </summary>
        public long BytesReceived => Interlocked.Read(ref _bytesReceived);

        /// <summary>
        /// Gets the total number of packets processed
        /// </summary>
        public long PacketsProcessed => Interlocked.Read(ref _packetsProcessed);

        /// <summary>
        /// Gets the total number of processing errors
        /// </summary>
        public long ProcessingErrors => Interlocked.Read(ref _processingErrors);

        /// <summary>
        /// Gets the capture start time
        /// </summary>
        public DateTime StartTime => _startTime;

        /// <summary>
        /// Gets the elapsed time since capture started
        /// </summary>
        public TimeSpan ElapsedTime => DateTime.UtcNow - _startTime;

        /// <summary>
        /// Gets the capture rate in packets per second
        /// </summary>
        public double CaptureRate
        {
            get
            {
                var elapsed = ElapsedTime.TotalSeconds;
                return elapsed > 0 ? PacketsCaptured / elapsed : 0;
            }
        }

        /// <summary>
        /// Gets the data rate in bytes per second
        /// </summary>
        public double DataRate
        {
            get
            {
                var elapsed = ElapsedTime.TotalSeconds;
                return elapsed > 0 ? BytesReceived / elapsed : 0;
            }
        }

        /// <summary>
        /// Gets the processing rate in packets per second
        /// </summary>
        public double ProcessingRate
        {
            get
            {
                var elapsed = ElapsedTime.TotalSeconds;
                return elapsed > 0 ? PacketsProcessed / elapsed : 0;
            }
        }

        /// <summary>
        /// Gets the drop rate as a percentage
        /// </summary>
        public double DropRate
        {
            get
            {
                var received = PacketsReceived;
                return received > 0 ? (PacketsDropped * 100.0) / received : 0;
            }
        }

        /// <summary>
        /// Gets the error rate as a percentage
        /// </summary>
        public double ErrorRate
        {
            get
            {
                var processed = PacketsProcessed;
                return processed > 0 ? (ProcessingErrors * 100.0) / processed : 0;
            }
        }

        /// <summary>
        /// Gets the data rate in megabits per second
        /// </summary>
        public double DataRateMbps => (DataRate * 8) / 1_000_000;

        /// <summary>
        /// Initializes a new instance of CaptureStatistics
        /// </summary>
        public CaptureStatistics()
        {
            _startTime = DateTime.UtcNow;
        }

        /// <summary>
        /// Increments the packets captured counter
        /// </summary>
        public void IncrementPacketsCaptured()
        {
            Interlocked.Increment(ref _packetsCaptured);
        }

        /// <summary>
        /// Increments the packets dropped counter
        /// </summary>
        /// <param name="count">Number of packets dropped</param>
        public void IncrementPacketsDropped(long count = 1)
        {
            Interlocked.Add(ref _packetsDropped, count);
        }

        /// <summary>
        /// Increments the packets received counter
        /// </summary>
        public void IncrementPacketsReceived()
        {
            Interlocked.Increment(ref _packetsReceived);
        }

        /// <summary>
        /// Adds bytes to the received counter
        /// </summary>
        /// <param name="bytes">Number of bytes received</param>
        public void AddBytesReceived(long bytes)
        {
            Interlocked.Add(ref _bytesReceived, bytes);
        }

        /// <summary>
        /// Increments the packets processed counter
        /// </summary>
        public void IncrementPacketsProcessed()
        {
            Interlocked.Increment(ref _packetsProcessed);
        }

        /// <summary>
        /// Increments the processing errors counter
        /// </summary>
        public void IncrementProcessingErrors()
        {
            Interlocked.Increment(ref _processingErrors);
        }

        /// <summary>
        /// Resets all statistics counters
        /// </summary>
        public void Reset()
        {
            Interlocked.Exchange(ref _packetsCaptured, 0);
            Interlocked.Exchange(ref _packetsDropped, 0);
            Interlocked.Exchange(ref _packetsReceived, 0);
            Interlocked.Exchange(ref _bytesReceived, 0);
            Interlocked.Exchange(ref _packetsProcessed, 0);
            Interlocked.Exchange(ref _processingErrors, 0);
        }

        /// <summary>
        /// Creates a snapshot of the current statistics
        /// </summary>
        public CaptureStatisticsSnapshot CreateSnapshot()
        {
            return new CaptureStatisticsSnapshot
            {
                PacketsCaptured = PacketsCaptured,
                PacketsDropped = PacketsDropped,
                PacketsReceived = PacketsReceived,
                BytesReceived = BytesReceived,
                PacketsProcessed = PacketsProcessed,
                ProcessingErrors = ProcessingErrors,
                StartTime = StartTime,
                SnapshotTime = DateTime.UtcNow,
                ElapsedTime = ElapsedTime,
                CaptureRate = CaptureRate,
                DataRate = DataRate,
                DataRateMbps = DataRateMbps,
                ProcessingRate = ProcessingRate,
                DropRate = DropRate,
                ErrorRate = ErrorRate
            };
        }

        public override string ToString()
        {
            return $"Captured: {PacketsCaptured.ToString("N0", CultureInfo.InvariantCulture)} packets, " +
                   $"Rate: {CaptureRate.ToString("F2", CultureInfo.InvariantCulture)} pkt/s ({DataRateMbps.ToString("F2", CultureInfo.InvariantCulture)} Mbps), " +
                   $"Dropped: {PacketsDropped.ToString("N0", CultureInfo.InvariantCulture)} ({DropRate.ToString("F2", CultureInfo.InvariantCulture)}%), " +
                   $"Errors: {ProcessingErrors.ToString("N0", CultureInfo.InvariantCulture)} ({ErrorRate.ToString("F2", CultureInfo.InvariantCulture)}%)";
        }
    }

    /// <summary>
    /// Immutable snapshot of capture statistics at a point in time
    /// </summary>
    public sealed class CaptureStatisticsSnapshot
    {
        public long PacketsCaptured { get; init; }
        public long PacketsDropped { get; init; }
        public long PacketsReceived { get; init; }
        public long BytesReceived { get; init; }
        public long PacketsProcessed { get; init; }
        public long ProcessingErrors { get; init; }
        public DateTime StartTime { get; init; }
        public DateTime SnapshotTime { get; init; }
        public TimeSpan ElapsedTime { get; init; }
        public double CaptureRate { get; init; }
        public double DataRate { get; init; }
        public double DataRateMbps { get; init; }
        public double ProcessingRate { get; init; }
        public double DropRate { get; init; }
        public double ErrorRate { get; init; }

        public override string ToString()
        {
            return $"Captured: {PacketsCaptured.ToString("N0", CultureInfo.InvariantCulture)} packets, " +
                   $"Rate: {CaptureRate.ToString("F2", CultureInfo.InvariantCulture)} pkt/s ({DataRateMbps.ToString("F2", CultureInfo.InvariantCulture)} Mbps), " +
                   $"Dropped: {PacketsDropped.ToString("N0", CultureInfo.InvariantCulture)} ({DropRate.ToString("F2", CultureInfo.InvariantCulture)}%), " +
                   $"Errors: {ProcessingErrors.ToString("N0", CultureInfo.InvariantCulture)} ({ErrorRate.ToString("F2", CultureInfo.InvariantCulture)}%)";
        }
    }
}
