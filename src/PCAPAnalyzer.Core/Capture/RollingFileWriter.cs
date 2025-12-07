using System;
using System.Collections.Concurrent;
using System.IO;
using System.IO.Compression;
using System.Threading;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Capture.Events;
using PCAPAnalyzer.Core.Capture.Models;

namespace PCAPAnalyzer.Core.Capture
{
    /// <summary>
    /// Manages rolling capture files with size and time-based rotation
    /// Implements circular buffer with automatic cleanup and compression
    /// </summary>
    public sealed class RollingFileWriter : IDisposable
    {
        private readonly CaptureConfiguration _configuration;
        private readonly string _baseOutputPath;
        private readonly ConcurrentQueue<string> _fileHistory;
        private FileStream? _currentFileStream;
        private string? _currentFilePath;
        private long _currentFileSize;
        private DateTime _currentFileStartTime;
        private readonly SemaphoreSlim _fileLock = new(1, 1);
        private readonly CancellationTokenSource _cancellationSource;
        private Task? _rotationMonitorTask;
        private long _currentFilePacketCount;
        private bool _disposed;

        /// <summary>
        /// Gets the current file path
        /// </summary>
        public string? CurrentFilePath => _currentFilePath;

        /// <summary>
        /// Gets the current file size in bytes
        /// </summary>
        public long CurrentFileSize => Interlocked.Read(ref _currentFileSize);

        /// <summary>
        /// Gets the current file packet count
        /// </summary>
        public long CurrentFilePacketCount => Interlocked.Read(ref _currentFilePacketCount);

        /// <summary>
        /// Gets the file history
        /// </summary>
        public string[] FileHistory => _fileHistory.ToArray();

        /// <summary>
        /// Event raised when file is rotated
        /// </summary>
        public event EventHandler<FileRotatedEventArgs>? FileRotated;

        /// <summary>
        /// Event raised when old files are compressed
        /// </summary>
        public event EventHandler<FileCompressedEventArgs>? FileCompressed;

        /// <summary>
        /// Event raised when old files are deleted
        /// </summary>
        public event EventHandler<FileDeletedEventArgs>? FileDeleted;

        /// <summary>
        /// Initializes a new rolling file writer
        /// </summary>
        public RollingFileWriter(CaptureConfiguration configuration)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));

            if (string.IsNullOrWhiteSpace(_configuration.OutputFilePath))
            {
                throw new ArgumentException("OutputFilePath must be specified", nameof(configuration));
            }

            // Validate and normalize path to prevent path traversal attacks
            _baseOutputPath = ValidateAndNormalizePath(_configuration.OutputFilePath);
            _fileHistory = new ConcurrentQueue<string>();
            _cancellationSource = new CancellationTokenSource();
        }

        /// <summary>
        /// Validates and normalizes a file path to prevent path traversal attacks
        /// </summary>
        /// <param name="path">The path to validate</param>
        /// <returns>The validated and normalized path</returns>
        /// <exception cref="UnauthorizedAccessException">Thrown when path is outside allowed directory</exception>
        private static string ValidateAndNormalizePath(string path)
        {
            // Get full path and normalize
            var fullPath = Path.GetFullPath(path);

            // Define allowed base directory (configured via environment variable or default)
            var allowedBasePath = Environment.GetEnvironmentVariable("PCAP_CAPTURE_DIR");
            if (string.IsNullOrEmpty(allowedBasePath))
            {
                allowedBasePath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "PCAPAnalyzer",
                    "Captures");
            }
            allowedBasePath = Path.GetFullPath(allowedBasePath);

            // Normalize paths for comparison by ensuring consistent directory separators
            var normalizedFullPath = fullPath.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
            var normalizedBasePath = allowedBasePath.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);

            // Ensure base path ends with separator to prevent false positives
            // (e.g., /tmp/test should not match /tmp/test2/file)
            if (!normalizedBasePath.EndsWith(Path.DirectorySeparatorChar))
            {
                normalizedBasePath += Path.DirectorySeparatorChar;
            }

            // Ensure full path or its directory starts with the allowed base path
            var directoryPath = Path.GetDirectoryName(normalizedFullPath);
            if (!string.IsNullOrEmpty(directoryPath) && !directoryPath.EndsWith(Path.DirectorySeparatorChar))
            {
                directoryPath += Path.DirectorySeparatorChar;
            }

            bool isValid = normalizedFullPath.StartsWith(normalizedBasePath, StringComparison.OrdinalIgnoreCase) ||
                           (!string.IsNullOrEmpty(directoryPath) && directoryPath.StartsWith(normalizedBasePath, StringComparison.OrdinalIgnoreCase));

            if (!isValid)
            {
                throw new UnauthorizedAccessException(
                    $"Capture file path '{path}' is outside the allowed capture directory '{allowedBasePath}'. " +
                    $"Set PCAP_CAPTURE_DIR environment variable to configure the allowed directory.");
            }

            return fullPath;
        }

        /// <summary>
        /// Initializes the writer and creates the first file
        /// </summary>
        public async Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            await _fileLock.WaitAsync(cancellationToken);
            try
            {
                // Ensure output directory exists
                var directory = Path.GetDirectoryName(_baseOutputPath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                // Create initial file
                await RotateFileAsync(RotationReason.UserRequested, cancellationToken);

                // Start rotation monitor
                _rotationMonitorTask = Task.Run(() => MonitorRotationAsync(_cancellationSource.Token), cancellationToken);
            }
            finally
            {
                _fileLock.Release();
            }
        }

        /// <summary>
        /// Writes packet data to the current file
        /// </summary>
        public async Task WritePacketAsync(byte[] packetData, CancellationToken cancellationToken = default)
        {
            if (packetData is null || packetData.Length == 0)
                return;

            await _fileLock.WaitAsync(cancellationToken);
            try
            {
                if (_currentFileStream is null)
                {
                    throw new InvalidOperationException("Writer not initialized. Call InitializeAsync first.");
                }

                // Write packet data
                await _currentFileStream.WriteAsync(packetData, cancellationToken);
                await _currentFileStream.FlushAsync(cancellationToken);

                // Update counters
                Interlocked.Add(ref _currentFileSize, packetData.Length);
                Interlocked.Increment(ref _currentFilePacketCount);

                // Check if rotation needed
                if (ShouldRotate())
                {
                    await RotateFileAsync(DetermineRotationReason(), cancellationToken);
                }
            }
            finally
            {
                _fileLock.Release();
            }
        }

        /// <summary>
        /// Writes packet data batch to the current file
        /// </summary>
        public async Task WritePacketBatchAsync(byte[][] packets, CancellationToken cancellationToken = default)
        {
            if (packets is null || packets.Length == 0)
                return;

            await _fileLock.WaitAsync(cancellationToken);
            try
            {
                if (_currentFileStream is null)
                {
                    throw new InvalidOperationException("Writer not initialized. Call InitializeAsync first.");
                }

                long totalBytes = 0;
                foreach (var packet in packets)
                {
                    await _currentFileStream.WriteAsync(packet, cancellationToken);
                    totalBytes += packet.Length;
                }

                await _currentFileStream.FlushAsync(cancellationToken);

                // Update counters
                Interlocked.Add(ref _currentFileSize, totalBytes);
                Interlocked.Add(ref _currentFilePacketCount, packets.Length);

                // Check if rotation needed
                if (ShouldRotate())
                {
                    await RotateFileAsync(DetermineRotationReason(), cancellationToken);
                }
            }
            finally
            {
                _fileLock.Release();
            }
        }

        /// <summary>
        /// Manually triggers file rotation
        /// </summary>
        public async Task RotateNowAsync(CancellationToken cancellationToken = default)
        {
            await _fileLock.WaitAsync(cancellationToken);
            try
            {
                await RotateFileAsync(RotationReason.UserRequested, cancellationToken);
            }
            finally
            {
                _fileLock.Release();
            }
        }

        /// <summary>
        /// Checks if rotation is needed
        /// </summary>
        private bool ShouldRotate()
        {
            // Check size limit
            if (_configuration.MaxFileSizeBytes > 0 &&
                _currentFileSize >= _configuration.MaxFileSizeBytes)
            {
                return true;
            }

            // Check time limit
            if (_configuration.MaxFileDuration > TimeSpan.Zero &&
                DateTime.UtcNow - _currentFileStartTime >= _configuration.MaxFileDuration)
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Determines the reason for rotation
        /// </summary>
        private RotationReason DetermineRotationReason()
        {
            if (_configuration.MaxFileSizeBytes > 0 &&
                _currentFileSize >= _configuration.MaxFileSizeBytes)
            {
                return RotationReason.SizeLimit;
            }

            if (_configuration.MaxFileDuration > TimeSpan.Zero &&
                DateTime.UtcNow - _currentFileStartTime >= _configuration.MaxFileDuration)
            {
                return RotationReason.TimeLimit;
            }

            return RotationReason.UserRequested;
        }

        /// <summary>
        /// Rotates to a new file
        /// </summary>
        private async Task RotateFileAsync(RotationReason reason, CancellationToken cancellationToken)
        {
            var oldFilePath = _currentFilePath;
            var oldFileSize = _currentFileSize;
            var oldPacketCount = _currentFilePacketCount;

            // Close current file
            if (_currentFileStream is not null)
            {
                await _currentFileStream.FlushAsync(cancellationToken);
                _currentFileStream.Close();
                _currentFileStream.Dispose();
                _currentFileStream = null;

                // Add to history
                if (!string.IsNullOrEmpty(oldFilePath))
                {
                    _fileHistory.Enqueue(oldFilePath);
                }
            }

            // Generate new file path with high-precision timestamp to ensure uniqueness
            var timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss_fff");
            var extension = _configuration.OutputFormat == CaptureFileFormat.Pcap ? "pcap" : "pcapng";
            var directory = Path.GetDirectoryName(_baseOutputPath) ?? ".";
            var baseFileName = Path.GetFileNameWithoutExtension(_baseOutputPath);
            _currentFilePath = Path.Combine(directory, $"{baseFileName}_{timestamp}.{extension}");

            // Create new file
            _currentFileStream = new FileStream(
                _currentFilePath,
                FileMode.Create,
                FileAccess.Write,
                FileShare.Read,
                bufferSize: 65536,
                useAsync: true);

            // Reset counters
            Interlocked.Exchange(ref _currentFileSize, 0);
            Interlocked.Exchange(ref _currentFilePacketCount, 0);
            _currentFileStartTime = DateTime.UtcNow;

            // Add new file to history immediately (even on first creation)
            _fileHistory.Enqueue(_currentFilePath);

            // Raise event
            if (!string.IsNullOrEmpty(oldFilePath))
            {
                FileRotated?.Invoke(this, new FileRotatedEventArgs
                {
                    SessionId = string.Empty,
                    OldFilePath = oldFilePath,
                    NewFilePath = _currentFilePath,
                    Reason = reason,
                    RotationTimestamp = DateTime.UtcNow,
                    FileSize = oldFileSize,
                    PacketCount = oldPacketCount
                });

                // Compress old file if configured
                if (_configuration.CompressOldFiles)
                {
                    _ = Task.Run(() => CompressFileAsync(oldFilePath, cancellationToken), cancellationToken);
                }
            }

            // Cleanup old files
            await CleanupOldFilesAsync(cancellationToken);
        }

        /// <summary>
        /// Monitors for time-based rotation
        /// </summary>
        private async Task MonitorRotationAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);

                    if (ShouldRotate())
                    {
                        await _fileLock.WaitAsync(cancellationToken);
                        try
                        {
                            if (ShouldRotate()) // Double-check after acquiring lock
                            {
                                await RotateFileAsync(DetermineRotationReason(), cancellationToken);
                            }
                        }
                        finally
                        {
                            _fileLock.Release();
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch
                {
                    // Continue monitoring despite errors
                }
            }
        }

        /// <summary>
        /// Compresses a capture file
        /// </summary>
        private async Task CompressFileAsync(string filePath, CancellationToken cancellationToken)
        {
            try
            {
                if (!File.Exists(filePath))
                    return;

                var compressedPath = filePath + ".gz";

                using (var sourceStream = File.OpenRead(filePath))
                using (var destStream = File.Create(compressedPath))
                using (var compressor = new GZipStream(destStream, CompressionLevel.Optimal))
                {
                    await sourceStream.CopyToAsync(compressor, cancellationToken);
                }

                // Delete original file
                File.Delete(filePath);

                // Update history
                if (_fileHistory.TryPeek(out var oldPath) && oldPath == filePath)
                {
                    _fileHistory.TryDequeue(out _);
                    _fileHistory.Enqueue(compressedPath);
                }

                FileCompressed?.Invoke(this, new FileCompressedEventArgs
                {
                    OriginalFilePath = filePath,
                    CompressedFilePath = compressedPath,
                    Timestamp = DateTime.UtcNow
                });
            }
            catch
            {
                // Compression is optional, continue on failure
            }
        }

        /// <summary>
        /// Cleans up old files beyond retention limit
        /// </summary>
        private async Task CleanupOldFilesAsync(CancellationToken cancellationToken)
        {
            if (_configuration.MaxRollingFiles <= 0)
                return;

            while (_fileHistory.Count > _configuration.MaxRollingFiles)
            {
                if (_fileHistory.TryDequeue(out var oldFile))
                {
                    try
                    {
                        if (File.Exists(oldFile))
                        {
                            File.Delete(oldFile);

                            FileDeleted?.Invoke(this, new FileDeletedEventArgs
                            {
                                FilePath = oldFile,
                                Reason = "Retention limit exceeded",
                                Timestamp = DateTime.UtcNow
                            });
                        }
                    }
                    catch
                    {
                        // Continue cleanup despite errors
                    }
                }
            }

            await Task.CompletedTask;
        }

        /// <summary>
        /// Flushes the current file
        /// </summary>
        public async Task FlushAsync(CancellationToken cancellationToken = default)
        {
            await _fileLock.WaitAsync(cancellationToken);
            try
            {
                if (_currentFileStream is not null)
                {
                    await _currentFileStream.FlushAsync(cancellationToken);
                }
            }
            finally
            {
                _fileLock.Release();
            }
        }

        public void Dispose()
        {
            if (_disposed) return;

            _cancellationSource.Cancel();

            _currentFileStream?.Dispose();
            _fileLock.Dispose();
            _cancellationSource.Dispose();

            _disposed = true;
        }
    }

    /// <summary>
    /// Event args for file compressed event
    /// </summary>
    public sealed class FileCompressedEventArgs : EventArgs
    {
        public string OriginalFilePath { get; init; } = string.Empty;
        public string CompressedFilePath { get; init; } = string.Empty;
        public DateTime Timestamp { get; init; }
    }

    /// <summary>
    /// Event args for file deleted event
    /// </summary>
    public sealed class FileDeletedEventArgs : EventArgs
    {
        public string FilePath { get; init; } = string.Empty;
        public string Reason { get; init; } = string.Empty;
        public DateTime Timestamp { get; init; }
    }
}
