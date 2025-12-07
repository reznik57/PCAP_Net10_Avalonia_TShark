using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.TShark.Configuration;

namespace PCAPAnalyzer.TShark;

/// <summary>
/// Parallel TShark service using PCAP chunking for multi-core processing.
/// Performance: 115s → 35-50s (3-4× speedup on 12-core system)
/// Memory: Aggressive RAM usage (2-5GB for 1.1M packets)
/// Supports: Windows native, WSL2, and Linux execution modes
/// </summary>
public sealed class ParallelTSharkService : ITSharkService, IDisposable
{
    private readonly ILogger<ParallelTSharkService> _logger;
    private readonly int _maxParallelism;
    private readonly int _chunkSize;
    private readonly string _tempDirectory;
    private readonly WiresharkToolInfo _editcapInfo;
    private readonly WiresharkToolInfo _tsharkInfo;
    private Channel<PacketInfo> _packetChannel = null!;
    private bool _isAnalyzing;
    private long _totalPacketsProcessed;

    public ParallelTSharkService(
        ILogger<ParallelTSharkService> logger,
        WiresharkToolInfo editcapInfo)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _editcapInfo = editcapInfo ?? throw new ArgumentNullException(nameof(editcapInfo));

        // Also detect tshark with same execution mode preference
        _tsharkInfo = WiresharkToolDetector.DetectTShark();
        if (!_tsharkInfo.IsAvailable)
        {
            throw new InvalidOperationException("tshark not available but required for ParallelTSharkService");
        }

        _maxParallelism = Environment.ProcessorCount; // Use all cores
        _chunkSize = 100_000; // Packets per chunk
        _tempDirectory = Path.Combine(Path.GetTempPath(), "pcap_chunks");

        _logger.LogInformation("ParallelTSharkService initialized: {Cores} cores, {ChunkSize} packets/chunk, Mode: {Mode}",
            _maxParallelism, _chunkSize, _editcapInfo.Mode);

        CreateNewChannel();
    }

    private void CreateNewChannel()
    {
        // Large bounded channel for aggressive buffering
        _packetChannel = Channel.CreateBounded<PacketInfo>(new BoundedChannelOptions(200000)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = false,
            SingleWriter = false, // Multiple writers (parallel chunks)
            AllowSynchronousContinuations = false
        });
    }

    public ChannelReader<PacketInfo> PacketReader => _packetChannel.Reader;
    public bool IsAnalyzing => _isAnalyzing;

    /// <summary>
    /// Starts parallel analysis by chunking PCAP and spawning multiple TShark processes.
    /// </summary>
    public async Task<bool> StartAnalysisAsync(string pcapPath, CancellationToken cancellationToken = default)
    {
        if (_isAnalyzing)
        {
            _logger.LogWarning("Analysis already in progress");
            return false;
        }

        if (!File.Exists(pcapPath))
        {
            _logger.LogError("PCAP file not found: {Path}", Path.GetFileName(pcapPath));
            return false;
        }

        // Editcap availability already verified in constructor
        // No need to re-check here

        _isAnalyzing = true;
        _totalPacketsProcessed = 0;
        CreateNewChannel();

        // Reset string pools for new analysis (memory optimization)
        // Note: Also called by AnalysisOrchestrator, but safe to call twice
        TSharkParserOptimized.ResetPools();

        try
        {
            DebugLogger.Log($"[ParallelTSharkService] Starting background processing for: {Path.GetFileName(pcapPath)}");

            // Start background processing
            _ = Task.Run(async () =>
            {
                try
                {
                    await ProcessPcapParallelAsync(pcapPath, cancellationToken);
                }
                catch (Exception ex)
                {
                    DebugLogger.Log($"[ParallelTSharkService] ❌ Background task failed: {ex.Message}");
                    _packetChannel.Writer.TryComplete(ex);
                }
            }, cancellationToken);

            // Give background task time to start before returning
            await Task.Delay(50, cancellationToken);

            DebugLogger.Log($"[ParallelTSharkService] Background task started, IsAnalyzing={_isAnalyzing}");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start parallel analysis");
            _isAnalyzing = false;
            return false;
        }
    }

    /// <summary>
    /// Main parallel processing workflow.
    /// STEP 1: Split PCAP into chunks (editcap)
    /// STEP 2: Process all chunks in parallel (12 TShark processes)
    /// STEP 3: Stream packets to channel (no sorting - caller handles)
    /// </summary>
    private async Task ProcessPcapParallelAsync(string pcapPath, CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();
        List<string> chunkFiles = [];

        DebugLogger.Log($"[ParallelTSharkService] ProcessPcapParallelAsync ENTERED for: {Path.GetFileName(pcapPath)}");

        try
        {
            DebugLogger.Log($"[ParallelTSharkService] 🚀 Starting PARALLEL PCAP analysis: {Path.GetFileName(pcapPath)} using {_maxParallelism} cores");

            // STEP 1: Split PCAP into chunks (3-5s for 1.1M packets)
            DebugLogger.Log($"[ParallelTSharkService] Starting editcap split...");
            var splitSw = Stopwatch.StartNew();
            chunkFiles = await SplitPcapAsync(pcapPath, cancellationToken);
            splitSw.Stop();

            DebugLogger.Log($"[ParallelTSharkService] ✂️  Split PCAP into {chunkFiles.Count} chunks in {splitSw.Elapsed.TotalSeconds:F1}s");

            // STEP 2: Process all chunks in parallel (17-25s for 12 chunks)
            DebugLogger.Log($"[ParallelTSharkService] Starting parallel chunk processing for {chunkFiles.Count} chunks...");
            var processSw = Stopwatch.StartNew();

            // Create semaphore to limit parallelism (prevent process explosion)
            using var semaphore = new SemaphoreSlim(_maxParallelism);

            // ✅ CRITICAL FIX: Calculate frame offsets for each chunk to avoid duplicate frame numbers
            // editcap creates chunks with frame.number starting from 1 in EACH chunk file
            // We must add (chunkIndex * chunkSize) to each frame number to get absolute frame numbers
            DebugLogger.Log($"[ParallelTSharkService] Creating {chunkFiles.Count} chunk tasks...");
            var chunkTasks = chunkFiles.Select(async (chunkPath, chunkIndex) =>
            {
                DebugLogger.Log($"[ParallelTSharkService] Chunk {chunkIndex} task started, waiting for semaphore...");
                await semaphore.WaitAsync(cancellationToken);
                DebugLogger.Log($"[ParallelTSharkService] Chunk {chunkIndex} acquired semaphore");
                try
                {
                    var frameOffset = chunkIndex * _chunkSize; // Chunk 0: offset=0, Chunk 1: offset=100000, etc.
                    DebugLogger.Log($"[ParallelTSharkService] Chunk {chunkIndex} calling ProcessChunkAsync...");
                    var result = await ProcessChunkAsync(chunkPath, chunkIndex, frameOffset, cancellationToken);
                    DebugLogger.Log($"[ParallelTSharkService] Chunk {chunkIndex} completed: {result} packets");
                    return result;
                }
                catch (Exception ex)
                {
                    DebugLogger.Log($"[ParallelTSharkService] Chunk {chunkIndex} FAILED: {ex.GetType().Name}: {ex.Message}");
                    DebugLogger.Log($"[ParallelTSharkService] Chunk {chunkIndex} stack: {ex.StackTrace}");
                    return 0;
                }
                finally
                {
                    semaphore.Release();
                }
            }).ToArray();

            DebugLogger.Log($"[ParallelTSharkService] Created {chunkTasks.Length} chunk tasks, calling Task.WhenAll...");
            var results = await Task.WhenAll(chunkTasks);
            DebugLogger.Log($"[ParallelTSharkService] Task.WhenAll completed with {results.Length} results");
            processSw.Stop();

            var totalPackets = results.Sum();
            _totalPacketsProcessed = totalPackets;

            DebugLogger.Log($"[ParallelTSharkService] ⚡ Parallel processing complete: {totalPackets:N0} packets in {processSw.Elapsed.TotalSeconds:F1}s");
            DebugLogger.Log($"[ParallelTSharkService] ✅ Total analysis time: {sw.Elapsed.TotalSeconds:F1}s");
        }
        catch (OperationCanceledException)
        {
            DebugLogger.Log("[ParallelTSharkService] Analysis cancelled by user");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[ParallelTSharkService] ❌ Error during parallel processing: {ex.Message}");
            DebugLogger.Log($"[ParallelTSharkService] Stack trace: {ex.StackTrace}");
        }
        finally
        {
            DebugLogger.Log($"[ParallelTSharkService] Entering finally block, processed {_totalPacketsProcessed} packets");

            // STEP 3: Cleanup temp files
            await CleanupChunksAsync(chunkFiles);

            // Log pool statistics for memory optimization verification
            var (ipCount, protoCount) = TSharkParserOptimized.GetPoolStats();
            DebugLogger.Log($"[ParallelTSharkService] 📊 String pools: {ipCount} unique IPs, {protoCount} unique protocols interned");

            DebugLogger.Log("[ParallelTSharkService] Completing packet channel...");
            _packetChannel.Writer.TryComplete();
            _isAnalyzing = false;
            DebugLogger.Log("[ParallelTSharkService] ProcessPcapParallelAsync EXITING");
        }
    }

    /// <summary>
    /// Splits PCAP file into chunks using editcap.
    /// Command: editcap -c 100000 input.pcap output.pcap
    /// Output: output_00000_20250704123456.pcap, output_00001_20250704123456.pcap, ...
    /// Supports WSL path conversion for Windows + WSL2 environments
    /// </summary>
    private async Task<List<string>> SplitPcapAsync(string inputPath, CancellationToken ct)
    {
        Directory.CreateDirectory(_tempDirectory);

        var chunkBaseName = $"chunk_{Guid.NewGuid():N}";
        var outputPattern = Path.Combine(_tempDirectory, $"{chunkBaseName}.pcap");

        // Convert paths for WSL if needed
        var effectiveInputPath = _editcapInfo.ConvertPathIfNeeded(inputPath);
        var effectiveOutputPath = _editcapInfo.ConvertPathIfNeeded(outputPattern);

        var arguments = $"-c {_chunkSize} \"{effectiveInputPath}\" \"{effectiveOutputPath}\"";
        var startInfo = _editcapInfo.CreateProcessStartInfo(arguments);

        _logger.LogDebug("Splitting PCAP: {Mode} editcap -c {ChunkSize} (input: {Input})",
            _editcapInfo.Mode, _chunkSize, Path.GetFileName(inputPath));

        using var process = Process.Start(startInfo)!;
        await process.WaitForExitAsync(ct);

        if (process.ExitCode != 0)
        {
            var error = await process.StandardError.ReadToEndAsync();
            throw new InvalidOperationException($"editcap failed (exit code {process.ExitCode}): {error}");
        }

        // Find all generated chunk files (editcap creates: chunk_xxx_00000_timestamp.pcap, chunk_xxx_00001_timestamp.pcap, ...)
        var chunkFiles = Directory.GetFiles(_tempDirectory, $"{chunkBaseName}_*.pcap")
            .OrderBy(f => f)
            .ToList();

        if (chunkFiles.Count == 0)
        {
            throw new InvalidOperationException($"editcap produced no chunk files in {_tempDirectory}");
        }

        _logger.LogDebug("Created {Count} chunk files in {Dir}", chunkFiles.Count, _tempDirectory);

        return chunkFiles;
    }

    /// <summary>
    /// Processes a single chunk with TShark.
    /// Uses optimized Span&lt;T&gt; parser from Phase 1 for maximum speed.
    /// </summary>
    /// <param name="frameOffset">Absolute frame offset to add to chunk-relative frame numbers (fixes editcap renumbering)</param>
    private async Task<int> ProcessChunkAsync(string chunkPath, int chunkIndex, int frameOffset, CancellationToken ct)
    {
        var packetCount = 0;
        var parseFailures = 0;
        var sw = Stopwatch.StartNew();

        try
        {
            var startInfo = BuildTSharkProcessStartInfo(chunkPath);

            // Log the command being executed (first chunk only to avoid log spam)
            if (chunkIndex == 0)
            {
                DebugLogger.Log($"[ParallelTSharkService] TShark command: {startInfo.FileName} {startInfo.Arguments?.Substring(0, Math.Min(200, startInfo.Arguments?.Length ?? 0))}...");
            }

            using var process = Process.Start(startInfo);
            if (process == null)
            {
                DebugLogger.Log($"[ParallelTSharkService] ❌ Chunk {chunkIndex}: Failed to start TShark process!");
                return 0;
            }

            DebugLogger.Log($"[ParallelTSharkService] Chunk {chunkIndex} TShark started, reading output...");

            // Parse TShark output line-by-line using optimized Span<T> parser
            var linesRead = 0;
            while (!ct.IsCancellationRequested)
            {
                var line = await process.StandardOutput.ReadLineAsync(ct);
                if (line == null) break;
                linesRead++;

                // Log first line of first chunk to verify format
                if (chunkIndex == 0 && linesRead == 1)
                {
                    var tabCount = line.Count(c => c == '\t');
                    DebugLogger.Log($"[ParallelTSharkService] First line has {tabCount} tabs, length={line.Length}");
                    DebugLogger.Log($"[ParallelTSharkService] First 200 chars: {line.Substring(0, Math.Min(200, line.Length))}");
                }

                // Use Phase 1 optimized parser (2.7× faster)
                var packet = TSharkParserOptimized.ParseLine(line.AsSpan());
                if (packet.HasValue)
                {
                    // ✅ CRITICAL FIX: Adjust frame number by chunk offset to get absolute frame number
                    // editcap renumbers frames starting from 1 in each chunk, we need original frame numbers
                    var correctedPacket = packet.Value with
                    {
                        FrameNumber = packet.Value.FrameNumber + (uint)frameOffset
                    };

                    await _packetChannel.Writer.WriteAsync(correctedPacket, ct);
                    packetCount++;
                }
                else
                {
                    parseFailures++;
                }
            }

            // Read stderr for any errors
            var stderr = await process.StandardError.ReadToEndAsync(ct);
            if (!string.IsNullOrWhiteSpace(stderr))
            {
                DebugLogger.Log($"[ParallelTSharkService] Chunk {chunkIndex} TShark stderr: {stderr.Substring(0, Math.Min(500, stderr.Length))}");
            }

            await process.WaitForExitAsync(ct);

            DebugLogger.Log($"[ParallelTSharkService] Chunk {chunkIndex}: {linesRead} lines read, {packetCount} packets parsed, {parseFailures} failures, exit={process.ExitCode}");

            return packetCount;
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("Chunk {Index} cancelled", chunkIndex);
            return packetCount;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing chunk {Index}", chunkIndex);
            return packetCount;
        }
    }

    /// <summary>
    /// Builds TShark process start info for a chunk file.
    /// Uses centralized TSharkFieldDefinitions for all 60 fields (core + credentials + OS fingerprint).
    /// Supports WSL path conversion for Windows + WSL2 environments
    /// </summary>
    private ProcessStartInfo BuildTSharkProcessStartInfo(string chunkPath)
    {
        // Convert path for WSL if needed
        var effectiveChunkPath = _tsharkInfo.ConvertPathIfNeeded(chunkPath);

        // Use centralized field definitions (same as TSharkService)
        var arguments = TSharkFieldDefinitions.BuildStreamingArguments(effectiveChunkPath);

        return _tsharkInfo.CreateProcessStartInfo(arguments);
    }

    /// <summary>
    /// Cleans up temporary chunk files.
    /// </summary>
    private async Task CleanupChunksAsync(List<string> chunkFiles)
    {
        if (chunkFiles.Count == 0)
            return;

        await Task.Run(() =>
        {
            var deletedCount = 0;
            foreach (var chunk in chunkFiles)
            {
                try
                {
                    if (File.Exists(chunk))
                    {
                        File.Delete(chunk);
                        deletedCount++;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to delete chunk: {File}", Path.GetFileName(chunk));
                }
            }

            _logger.LogDebug("Cleaned up {Count}/{Total} chunk files", deletedCount, chunkFiles.Count);

            // Try to remove temp directory if empty
            try
            {
                if (Directory.Exists(_tempDirectory) && !Directory.EnumerateFileSystemEntries(_tempDirectory).Any())
                {
                    Directory.Delete(_tempDirectory);
                    _logger.LogDebug("Removed empty temp directory: {Dir}", _tempDirectory);
                }
            }
            catch
            {
                // Ignore cleanup failures
            }
        });
    }


    /// <summary>
    /// Gets total packet count using capinfos (fast) or tshark (fallback).
    /// capinfos reads pcap header only (~1-2 seconds vs 30-95 seconds for tshark).
    /// Supports WSL path conversion for Windows + WSL2 environments
    /// </summary>
    public async Task<long> GetTotalPacketCountAsync(string pcapPath, PCAPAnalyzer.Core.Orchestration.ProgressCoordinator? progressCoordinator = null)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            // ✅ PERFORMANCE: Try capinfos first (reads pcap header, ~1-2 seconds vs 30-95 seconds)
            var capinfosCount = await GetPacketCountViaCapinfosAsync(pcapPath, progressCoordinator);
            if (capinfosCount > 0)
            {
                _logger.LogDebug("Total packets via capinfos: {Count:N0} (took {Duration:F1}s)", capinfosCount, sw.Elapsed.TotalSeconds);
                return capinfosCount;
            }

            // Fallback to TShark if capinfos unavailable or fails
            DebugLogger.Log("[ParallelTSharkService] capinfos unavailable or failed, falling back to TShark packet count...");
            return await GetPacketCountViaTSharkAsync(pcapPath, progressCoordinator, sw);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get packet count");
            return 0;
        }
        finally
        {
            sw.Stop();
        }
    }

    /// <summary>
    /// Fast packet count using capinfos (reads pcap header only, ~1-2 seconds for any file size).
    /// </summary>
    private async Task<long> GetPacketCountViaCapinfosAsync(string pcapPath, PCAPAnalyzer.Core.Orchestration.ProgressCoordinator? progressCoordinator)
    {
        var capinfosInfo = WiresharkToolDetector.DetectCapinfos();
        if (!capinfosInfo.IsAvailable)
        {
            DebugLogger.Log("[ParallelTSharkService] capinfos not available");
            return 0;
        }

        progressCoordinator?.ReportCounting(10, "Reading packet count from PCAP header (fast)...");
        DebugLogger.Log($"[ParallelTSharkService] Using capinfos for fast packet count: {capinfosInfo.Description}");

        try
        {
            var convertedPath = capinfosInfo.ConvertPathIfNeeded(pcapPath);
            // ✅ FIX: Use -Mc for machine-readable output (exact count without k/M suffixes)
            var psi = capinfosInfo.CreateProcessStartInfo($"-Mc \"{convertedPath}\"");

            using var process = Process.Start(psi);
            if (process == null)
            {
                DebugLogger.Log("[ParallelTSharkService] Failed to start capinfos process");
                return 0;
            }

            var output = await process.StandardOutput.ReadToEndAsync();
            var errorOutput = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();

            if (process.ExitCode != 0)
            {
                DebugLogger.Log($"[ParallelTSharkService] capinfos failed with exit code {process.ExitCode}: {errorOutput}");
                return 0;
            }

            // Parse output - look for "Number of packets" line
            // With -M flag: exact number "5835139", without: may show "5835 k" suffix
            foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                if (line.Contains("Number of packets", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = line.Split(new[] { '=', ':' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2)
                    {
                        var numberPart = parts[^1].Trim();
                        var count = ParseCapinfosPacketCount(numberPart);
                        if (count > 0)
                        {
                            progressCoordinator?.ReportCounting(100, $"Counted {count:N0} packets (via capinfos)");
                            DebugLogger.Log($"[ParallelTSharkService] ⚡ capinfos packet count: {count:N0}");
                            return count;
                        }
                    }
                }
            }

            DebugLogger.Log($"[ParallelTSharkService] capinfos output parsing failed: {output}");
            return 0;
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[ParallelTSharkService] capinfos exception: {ex.Message}");
            return 0;
        }
    }

    /// <summary>
    /// Parses capinfos packet count format which uses k/M suffixes with space.
    /// Examples: "5835139" → 5835139, "5835 k" → 5835000, "5 M" → 5000000
    /// </summary>
    private static long ParseCapinfosPacketCount(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return 0;

        value = value.Trim();

        // Check for k (thousands) or M (millions) suffix
        long multiplier = 1;
        if (value.EndsWith(" k", StringComparison.OrdinalIgnoreCase) ||
            value.EndsWith("k", StringComparison.OrdinalIgnoreCase))
        {
            multiplier = 1000;
            value = value.TrimEnd('k', 'K', ' ');
        }
        else if (value.EndsWith(" M", StringComparison.OrdinalIgnoreCase) ||
                 value.EndsWith("M", StringComparison.OrdinalIgnoreCase))
        {
            multiplier = 1_000_000;
            value = value.TrimEnd('m', 'M', ' ');
        }

        // Remove any remaining whitespace and commas
        value = value.Trim().Replace(",", "", StringComparison.Ordinal).Replace(" ", "", StringComparison.Ordinal);

        if (long.TryParse(value, NumberStyles.Any, CultureInfo.InvariantCulture, out var count))
        {
            return count * multiplier;
        }

        return 0;
    }

    /// <summary>
    /// Slow packet count using TShark (reads all packets, can take 30-95 seconds for large files).
    /// </summary>
    private async Task<long> GetPacketCountViaTSharkAsync(string pcapPath, PCAPAnalyzer.Core.Orchestration.ProgressCoordinator? progressCoordinator, Stopwatch sw)
    {
        var effectivePcapPath = _tsharkInfo.ConvertPathIfNeeded(pcapPath);
        var arguments = $"-r \"{effectivePcapPath}\" -T fields -e frame.number";
        var startInfo = _tsharkInfo.CreateProcessStartInfo(arguments);

        using var process = Process.Start(startInfo)!;

        progressCoordinator?.ReportCounting(0, "Starting packet count (slow method)...");

        string? lastLine = null;
        long lineCount = 0;
        var progressReportTimer = System.Diagnostics.Stopwatch.StartNew();

        while (true)
        {
            var line = await process.StandardOutput.ReadLineAsync();
            if (line == null) break;

            if (!string.IsNullOrWhiteSpace(line))
            {
                lastLine = line.Trim();
                lineCount++;

                if (progressReportTimer.Elapsed.TotalSeconds >= 2.0)
                {
                    var totalElapsed = sw.Elapsed.TotalSeconds;
                    var estimatedProgress = Math.Min(95, (int)(totalElapsed / 0.3));
                    progressCoordinator?.ReportCounting(estimatedProgress, $"Counting packets... {lineCount:N0} detected", lineCount);
                    progressReportTimer.Restart();
                }
            }
        }

        await process.WaitForExitAsync();

        if (lastLine != null && long.TryParse(lastLine, out var count))
        {
            _logger.LogDebug("Total packet count ({Mode}): {Count:N0} (took {Duration:F1}s)", _tsharkInfo.Mode, count, sw.Elapsed.TotalSeconds);
            progressCoordinator?.ReportCounting(100, $"Counted {count:N0} packets");
            return count;
        }

        _logger.LogWarning("Failed to parse packet count from tshark output");
        return 0;
    }

    public Task StopAnalysisAsync()
    {
        _isAnalyzing = false;
        _packetChannel.Writer.TryComplete();
        _logger.LogInformation("Analysis stopped");
        return Task.CompletedTask;
    }

    /// <summary>
    /// Extracts capture time range (first/last packet timestamps) from a PCAP file.
    /// </summary>
    public async Task<(DateTime? FirstPacketTime, DateTime? LastPacketTime)> GetCaptureTimeRangeAsync(string pcapPath)
    {
        try
        {
            if (!File.Exists(pcapPath))
            {
                return (null, null);
            }

            // Get first packet timestamp
            var firstPacketTime = await GetFirstPacketTimestampAsync(pcapPath);

            // For last packet, skip for large files > 500MB
            // 500MB files typically complete in 2-3 seconds
            var fileSize = new FileInfo(pcapPath).Length;
            DateTime? lastPacketTime = null;

            if (fileSize < 500 * 1024 * 1024)
            {
                lastPacketTime = await GetLastPacketTimestampAsync(pcapPath);
            }

            return (firstPacketTime, lastPacketTime);
        }
        catch
        {
            return (null, null);
        }
    }

    private async Task<DateTime?> GetFirstPacketTimestampAsync(string pcapPath)
    {
        try
        {
            var effectivePath = _tsharkInfo.ConvertPathIfNeeded(pcapPath);
            var arguments = $"-r \"{effectivePath}\" -T fields -e frame.time_epoch -c 1";
            var startInfo = _tsharkInfo.CreateProcessStartInfo(arguments);

            using var process = Process.Start(startInfo);
            if (process == null) return null;

            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            if (double.TryParse(output.Trim(), System.Globalization.NumberStyles.Float,
                    System.Globalization.CultureInfo.InvariantCulture, out var epoch))
            {
                return DateTimeOffset.FromUnixTimeMilliseconds((long)(epoch * 1000)).LocalDateTime;
            }
            return null;
        }
        catch
        {
            return null;
        }
    }

    private async Task<DateTime?> GetLastPacketTimestampAsync(string pcapPath)
    {
        try
        {
            var effectivePath = _tsharkInfo.ConvertPathIfNeeded(pcapPath);
            var arguments = $"-r \"{effectivePath}\" -T fields -e frame.time_epoch";
            var startInfo = _tsharkInfo.CreateProcessStartInfo(arguments);

            using var process = Process.Start(startInfo);
            if (process == null) return null;

            string? lastLine = null;
            while (await process.StandardOutput.ReadLineAsync() is { } line)
            {
                if (!string.IsNullOrWhiteSpace(line))
                    lastLine = line;
            }
            await process.WaitForExitAsync();

            if (lastLine != null && double.TryParse(lastLine.Trim(), System.Globalization.NumberStyles.Float,
                    System.Globalization.CultureInfo.InvariantCulture, out var epoch))
            {
                return DateTimeOffset.FromUnixTimeMilliseconds((long)(epoch * 1000)).LocalDateTime;
            }
            return null;
        }
        catch
        {
            return null;
        }
    }

    public void ResetService()
    {
        // Aggressive reset - no waiting
        if (_isAnalyzing)
        {
            _isAnalyzing = false;
            _packetChannel.Writer.TryComplete();
        }

        CreateNewChannel();
        _totalPacketsProcessed = 0;
        _logger.LogDebug("Service reset");
    }

    public PacketStatistics GetStatistics()
    {
        // Return simple stats (orchestrator tracks detailed stats)
        return new PacketStatistics
        {
            TotalPackets = (int)_totalPacketsProcessed,
            PacketsPerSecond = 0 // Calculated by orchestrator
        };
    }

    /// <summary>
    /// Async disposal - gracefully stops analysis.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (_isAnalyzing)
        {
            await StopAnalysisAsync().ConfigureAwait(false);
        }

        _packetChannel.Writer.TryComplete();
        _logger.LogDebug("ParallelTSharkService disposed asynchronously");
    }

    /// <summary>
    /// Synchronous disposal - aggressive cleanup.
    /// </summary>
    public void Dispose()
    {
        _isAnalyzing = false;
        _packetChannel.Writer.TryComplete();
        _logger.LogDebug("ParallelTSharkService disposed synchronously");
    }
}
