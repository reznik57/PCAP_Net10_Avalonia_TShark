using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Threading;
using System.Threading.Tasks;

namespace PCAPAnalyzer.Core.Performance
{
    /// <summary>
    /// High-performance memory-mapped file reader for large PCAP files
    /// Provides efficient random access without loading entire file into memory
    /// </summary>
    public sealed class MemoryMappedFileReader : IDisposable
    {
        private readonly string _filePath;
        private readonly FileStream _fileStream;
        private readonly MemoryMappedFile _memoryMappedFile;
        private readonly long _fileSize;
        private bool _disposed;

        /// <summary>
        /// Gets the size of the file in bytes
        /// </summary>
        public long FileSize => _fileSize;

        /// <summary>
        /// Gets the file path
        /// </summary>
        public string FilePath => _filePath;

        /// <summary>
        /// Initializes a new memory-mapped file reader
        /// </summary>
        /// <param name="filePath">Path to the file</param>
        /// <param name="mapName">Optional name for the memory mapping</param>
        public MemoryMappedFileReader(string filePath, string? mapName = null)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException("File not found", filePath);

            _filePath = filePath;

            // Open file stream with optimal settings for large files
            _fileStream = new FileStream(
                filePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 8192,
                FileOptions.SequentialScan
            );

            _fileSize = _fileStream.Length;

            // Create memory-mapped file
            _memoryMappedFile = MemoryMappedFile.CreateFromFile(
                _fileStream,
                mapName,
                0, // Map entire file
                MemoryMappedFileAccess.Read,
                HandleInheritability.None,
                leaveOpen: false
            );
        }

        /// <summary>
        /// Reads a block of data from the specified offset
        /// </summary>
        /// <param name="offset">Starting position in the file</param>
        /// <param name="length">Number of bytes to read</param>
        /// <returns>Byte array containing the data</returns>
        public byte[] ReadBlock(long offset, int length)
        {
            if (offset < 0 || offset >= _fileSize)
                throw new ArgumentOutOfRangeException(nameof(offset));

            if (length < 0 || offset + length > _fileSize)
                throw new ArgumentOutOfRangeException(nameof(length));

            using var accessor = _memoryMappedFile.CreateViewAccessor(
                offset,
                length,
                MemoryMappedFileAccess.Read
            );

            var buffer = new byte[length];
            accessor.ReadArray(0, buffer, 0, length);
            return buffer;
        }

        /// <summary>
        /// Reads data into an existing buffer
        /// </summary>
        /// <param name="offset">Starting position in the file</param>
        /// <param name="buffer">Buffer to read into</param>
        /// <param name="bufferOffset">Offset in the buffer</param>
        /// <param name="count">Number of bytes to read</param>
        /// <returns>Number of bytes actually read</returns>
        public int ReadIntoBuffer(long offset, byte[] buffer, int bufferOffset, int count)
        {
            if (offset < 0 || offset >= _fileSize)
                throw new ArgumentOutOfRangeException(nameof(offset));

            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));

            // Adjust count if it would exceed file size
            long bytesAvailable = _fileSize - offset;
            int bytesToRead = (int)Math.Min(count, bytesAvailable);

            using var accessor = _memoryMappedFile.CreateViewAccessor(
                offset,
                bytesToRead,
                MemoryMappedFileAccess.Read
            );

            accessor.ReadArray(0, buffer, bufferOffset, bytesToRead);
            return bytesToRead;
        }

        /// <summary>
        /// Reads data asynchronously in chunks
        /// </summary>
        /// <param name="offset">Starting position</param>
        /// <param name="length">Total length to read</param>
        /// <param name="chunkSize">Size of each chunk</param>
        /// <param name="chunkCallback">Callback for each chunk</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public async Task ReadChunksAsync(
            long offset,
            long length,
            int chunkSize,
            Action<byte[], int> chunkCallback,
            CancellationToken cancellationToken = default)
        {
            if (offset < 0 || offset >= _fileSize)
                throw new ArgumentOutOfRangeException(nameof(offset));

            if (chunkSize <= 0)
                throw new ArgumentOutOfRangeException(nameof(chunkSize));

            long remaining = Math.Min(length, _fileSize - offset);
            long currentOffset = offset;
            var buffer = new byte[chunkSize];

            while (remaining > 0 && !cancellationToken.IsCancellationRequested)
            {
                int bytesToRead = (int)Math.Min(chunkSize, remaining);

                // Read on thread pool to avoid blocking
                await Task.Run(() =>
                {
                    int bytesRead = ReadIntoBuffer(currentOffset, buffer, 0, bytesToRead);
                    chunkCallback(buffer, bytesRead);
                }, cancellationToken);

                currentOffset += bytesToRead;
                remaining -= bytesToRead;
            }
        }

        /// <summary>
        /// Creates a view stream for reading a section of the file
        /// </summary>
        /// <param name="offset">Starting position</param>
        /// <param name="length">Length of the view</param>
        /// <returns>Stream for reading the specified section</returns>
        public Stream CreateViewStream(long offset, long length)
        {
            if (offset < 0 || offset >= _fileSize)
                throw new ArgumentOutOfRangeException(nameof(offset));

            if (length < 0 || offset + length > _fileSize)
                throw new ArgumentOutOfRangeException(nameof(length));

            return _memoryMappedFile.CreateViewStream(
                offset,
                length,
                MemoryMappedFileAccess.Read
            );
        }

        /// <summary>
        /// Searches for a byte pattern in the file
        /// </summary>
        /// <param name="pattern">Pattern to search for</param>
        /// <param name="startOffset">Starting offset for search</param>
        /// <param name="searchLength">Length to search (0 for entire file)</param>
        /// <returns>Offset of first occurrence, or -1 if not found</returns>
        public long FindPattern(byte[] pattern, long startOffset = 0, long searchLength = 0)
        {
            if (pattern is null || pattern.Length == 0)
                throw new ArgumentException("Pattern cannot be null or empty", nameof(pattern));

            if (startOffset < 0 || startOffset >= _fileSize)
                return -1;

            long endOffset = searchLength > 0
                ? Math.Min(startOffset + searchLength, _fileSize)
                : _fileSize;

            const int bufferSize = 64 * 1024; // 64 KB chunks
            var buffer = new byte[bufferSize + pattern.Length - 1];
            long currentOffset = startOffset;

            while (currentOffset < endOffset)
            {
                long remaining = endOffset - currentOffset;
                int bytesToRead = (int)Math.Min(buffer.Length, remaining);

                int bytesRead = ReadIntoBuffer(currentOffset, buffer, 0, bytesToRead);
                if (bytesRead == 0) break;

                // Search for pattern in buffer
                for (int i = 0; i <= bytesRead - pattern.Length; i++)
                {
                    bool found = true;
                    for (int j = 0; j < pattern.Length; j++)
                    {
                        if (buffer[i + j] != pattern[j])
                        {
                            found = false;
                            break;
                        }
                    }

                    if (found)
                    {
                        return currentOffset + i;
                    }
                }

                // Move forward, accounting for overlap
                currentOffset += bytesRead - pattern.Length + 1;
            }

            return -1; // Not found
        }

        /// <summary>
        /// Gets memory usage statistics
        /// </summary>
        public MemoryMappedFileStatistics GetStatistics()
        {
            return new MemoryMappedFileStatistics
            {
                FilePath = _filePath,
                FileSize = _fileSize,
                FileSizeMB = _fileSize / (1024.0 * 1024.0),
                IsDisposed = _disposed
            };
        }

        public void Dispose()
        {
            if (_disposed) return;

            _memoryMappedFile?.Dispose();
            _fileStream?.Dispose();

            _disposed = true;
        }
    }

    /// <summary>
    /// Statistics for memory-mapped file reader
    /// </summary>
    public sealed class MemoryMappedFileStatistics
    {
        public string FilePath { get; init; } = string.Empty;
        public long FileSize { get; init; }
        public double FileSizeMB { get; init; }
        public bool IsDisposed { get; init; }

        public override string ToString()
        {
            return $"File: {FilePath}, Size: {FileSizeMB:F2} MB, Disposed: {IsDisposed}";
        }
    }
}
