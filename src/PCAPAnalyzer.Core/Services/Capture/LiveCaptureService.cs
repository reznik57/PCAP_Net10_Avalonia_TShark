using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PCAPAnalyzer.Core.Models.Capture;

namespace PCAPAnalyzer.Core.Services.Capture;

/// <summary>
/// Live packet capture service using TShark
/// </summary>
/// <remarks>
/// OBSOLETE: This implementation is being replaced by LiveCaptureManagerAdapter
/// which provides better integration with the backend LiveCaptureManager.
/// Use LiveCaptureManagerAdapter instead for new code.
/// </remarks>
[Obsolete("Use LiveCaptureManagerAdapter instead. This class will be removed in a future version.")]
public class LiveCaptureService : ILiveCaptureService, IDisposable
{
    private readonly ILogger<LiveCaptureService> _logger;
    private readonly INetworkInterfaceManager _interfaceManager;
    private readonly string _tsharkPath;
    private Process? _captureProcess;
    private CaptureSession? _currentSession;
    private CancellationTokenSource? _captureCts;
    private Task? _captureTask;
    private readonly Channel<LivePacketData> _packetChannel;
    private readonly ConcurrentQueue<CaptureSession> _sessionHistory;
    private readonly SemaphoreSlim _sessionLock = new(1, 1);
    private long _packetSequence;
    private DateTime _lastStatsUpdate = DateTime.UtcNow;
    private long _lastPacketCount;
    private long _lastByteCount;

    public CaptureSession? CurrentSession => _currentSession;

    public event EventHandler<LivePacketData>? PacketCaptured;
    public event EventHandler<CaptureSessionStats>? StatisticsUpdated;
    public event EventHandler<CaptureStatus>? StatusChanged;

    public LiveCaptureService(
        ILogger<LiveCaptureService> logger,
        INetworkInterfaceManager interfaceManager,
        string? tsharkPath = null)
    {
        _logger = logger;
        _interfaceManager = interfaceManager;
        _tsharkPath = tsharkPath ?? FindTSharkPath();
        _packetChannel = Channel.CreateUnbounded<LivePacketData>(new UnboundedChannelOptions
        {
            SingleReader = false,
            SingleWriter = false
        });
        _sessionHistory = new ConcurrentQueue<CaptureSession>();
    }

    /// <inheritdoc/>
    public async Task<CaptureSession> StartCaptureAsync(CaptureConfiguration config, CancellationToken cancellationToken = default)
    {
        await _sessionLock.WaitAsync(cancellationToken);
        try
        {
            if (_currentSession?.IsActive == true)
            {
                throw new InvalidOperationException("A capture session is already active. Stop it before starting a new one.");
            }

            config.Validate();

            // Get interface details
            var iface = await _interfaceManager.GetInterfaceByIdAsync(config.InterfaceId, cancellationToken);
            if (iface == null)
            {
                throw new ArgumentException($"Interface '{config.InterfaceId}' not found", nameof(config));
            }

            // Create new session
            _currentSession = new CaptureSession
            {
                InterfaceName = iface.Name,
                CaptureFilter = config.CaptureFilter,
                Status = CaptureStatus.Initializing
            };

            _logger.LogInformation("Starting capture on interface {Interface} with filter '{Filter}'",
                iface.Name, config.CaptureFilter);

            // Reset counters
            _packetSequence = 0;
            _lastPacketCount = 0;
            _lastByteCount = 0;
            _lastStatsUpdate = DateTime.UtcNow;

            // Start capture process
            _captureCts = new CancellationTokenSource();
            _captureTask = StartCaptureProcessAsync(config, _captureCts.Token);

            // Update status
            _currentSession.Status = CaptureStatus.Capturing;
            OnStatusChanged(CaptureStatus.Capturing);

            _sessionHistory.Enqueue(_currentSession);

            return _currentSession;
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    /// <inheritdoc/>
    public async Task StopCaptureAsync(CancellationToken cancellationToken = default)
    {
        await _sessionLock.WaitAsync(cancellationToken);
        try
        {
            if (_currentSession == null || !_currentSession.IsActive)
            {
                return;
            }

            _logger.LogInformation("Stopping capture session {SessionId}", _currentSession.SessionId);

            // Cancel capture
            _captureCts?.Cancel();

            // Wait for capture task to complete
            if (_captureTask != null)
            {
                try
                {
                    await _captureTask.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
                }
                catch (TimeoutException)
                {
                    _logger.LogWarning("Capture task did not complete within timeout");
                }
            }

            // Stop TShark process
            if (_captureProcess != null && !_captureProcess.HasExited)
            {
                try
                {
                    _captureProcess.Kill(true);
                    await _captureProcess.WaitForExitAsync(cancellationToken);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error stopping TShark process");
                }
            }

            // Update session
            _currentSession.EndTime = DateTime.UtcNow;
            _currentSession.Status = CaptureStatus.Stopped;
            OnStatusChanged(CaptureStatus.Stopped);

            _logger.LogInformation("Capture session stopped. Captured {PacketCount} packets in {Duration}",
                _currentSession.Stats.TotalPackets, _currentSession.Duration);
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    /// <inheritdoc/>
    public async Task PauseCaptureAsync(CancellationToken cancellationToken = default)
    {
        await _sessionLock.WaitAsync(cancellationToken);
        try
        {
            if (_currentSession?.Status != CaptureStatus.Capturing)
            {
                throw new InvalidOperationException("No active capture session to pause");
            }

            _currentSession.Status = CaptureStatus.Paused;
            OnStatusChanged(CaptureStatus.Paused);

            _logger.LogInformation("Capture session paused");
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    /// <inheritdoc/>
    public async Task ResumeCaptureAsync(CancellationToken cancellationToken = default)
    {
        await _sessionLock.WaitAsync(cancellationToken);
        try
        {
            if (_currentSession?.Status != CaptureStatus.Paused)
            {
                throw new InvalidOperationException("No paused capture session to resume");
            }

            _currentSession.Status = CaptureStatus.Capturing;
            OnStatusChanged(CaptureStatus.Capturing);

            _logger.LogInformation("Capture session resumed");
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    /// <inheritdoc/>
    public async Task<CaptureSessionStats> GetCurrentStatisticsAsync(CancellationToken cancellationToken = default)
    {
        return await Task.FromResult(_currentSession?.Stats ?? new CaptureSessionStats());
    }

    /// <inheritdoc/>
    public async Task<List<CaptureSession>> GetSessionHistoryAsync(int maxSessions = 100, CancellationToken cancellationToken = default)
    {
        var sessions = _sessionHistory.ToList();
        return await Task.FromResult(sessions.TakeLast(maxSessions).ToList());
    }

    /// <inheritdoc/>
    public async Task<string> ExportCaptureAsync(string outputPath, CancellationToken cancellationToken = default)
    {
        if (_currentSession == null)
        {
            throw new InvalidOperationException("No capture session available to export");
        }

        if (_currentSession.CaptureFiles.Count == 0)
        {
            throw new InvalidOperationException("No capture files available to export");
        }

        // If single file, copy it
        if (_currentSession.CaptureFiles.Count == 1)
        {
            File.Copy(_currentSession.CaptureFiles[0], outputPath, true);
            return outputPath;
        }

        // Merge multiple files using mergecap
        var mergecapPath = Path.Combine(Path.GetDirectoryName(_tsharkPath) ?? "", "mergecap");
        if (!File.Exists(mergecapPath))
        {
            mergecapPath += ".exe"; // Windows
        }

        if (!File.Exists(mergecapPath))
        {
            throw new FileNotFoundException("mergecap utility not found. Cannot merge capture files.");
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = mergecapPath,
            Arguments = $"-w \"{outputPath}\" {string.Join(" ", _currentSession.CaptureFiles.Select(f => $"\"{f}\""))}",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(startInfo);
        if (process == null)
        {
            throw new InvalidOperationException("Failed to start mergecap process");
        }

        await process.WaitForExitAsync(cancellationToken);

        if (process.ExitCode != 0)
        {
            var error = await process.StandardError.ReadToEndAsync(cancellationToken);
            throw new InvalidOperationException($"mergecap failed: {error}");
        }

        return outputPath;
    }

    /// <inheritdoc/>
    public async Task CleanupOldCapturesAsync(CancellationToken cancellationToken = default)
    {
        var sessions = _sessionHistory.Where(s => !s.IsActive).ToList();
        var cutoffDate = DateTime.UtcNow.AddDays(-7); // Default 7 days retention

        foreach (var session in sessions)
        {
            if (session.EndTime < cutoffDate)
            {
                foreach (var file in session.CaptureFiles)
                {
                    try
                    {
                        if (File.Exists(file))
                        {
                            File.Delete(file);
                            _logger.LogInformation("Deleted old capture file: {File}", file);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to delete capture file: {File}", file);
                    }
                }
            }
        }

        await Task.CompletedTask;
    }

    private async Task StartCaptureProcessAsync(CaptureConfiguration config, CancellationToken cancellationToken)
    {
        try
        {
            var outputFile = Path.Combine(config.OutputDirectory,
                $"{config.FileNamePrefix}_{DateTime.UtcNow:yyyyMMdd_HHmmss}.pcapng");

            Directory.CreateDirectory(config.OutputDirectory);

            // Build TShark arguments
            var args = new StringBuilder();
            args.Append($"-i {config.InterfaceId} ");
            args.Append($"-w \"{outputFile}\" ");

            if (!string.IsNullOrWhiteSpace(config.CaptureFilter))
            {
                args.Append($"-f \"{config.CaptureFilter}\" ");
            }

            if (config.PromiscuousMode)
            {
                args.Append("-p ");
            }

            args.Append($"-s {config.SnapshotLength} ");

            if (config.MaxFileSizeMB > 0)
            {
                args.Append($"-b filesize:{config.MaxFileSizeMB * 1024} ");
                if (config.MaxRollingFiles > 0)
                {
                    args.Append($"-b files:{config.MaxRollingFiles} ");
                }
            }

            if (config.MaxDurationSeconds > 0)
            {
                args.Append($"-a duration:{config.MaxDurationSeconds} ");
            }

            if (config.MaxPackets > 0)
            {
                args.Append($"-c {config.MaxPackets} ");
            }

            // Add live output for packet capture
            args.Append("-T pdml ");

            _logger.LogDebug("Starting TShark with arguments: {Args}", args);

            var startInfo = new ProcessStartInfo
            {
                FileName = _tsharkPath,
                Arguments = args.ToString(),
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            _captureProcess = Process.Start(startInfo);
            if (_captureProcess == null)
            {
                throw new InvalidOperationException("Failed to start TShark process");
            }

            if (_currentSession != null)
            {
                _currentSession.CaptureFiles.Add(outputFile);
            }

            // Read output
            _ = Task.Run(() => ReadCaptureOutputAsync(_captureProcess, cancellationToken), cancellationToken);

            // Monitor statistics
            _ = Task.Run(() => MonitorStatisticsAsync(cancellationToken), cancellationToken);

            await _captureProcess.WaitForExitAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during packet capture");
            if (_currentSession != null)
            {
                _currentSession.Status = CaptureStatus.Failed;
                _currentSession.ErrorMessage = ex.Message;
                OnStatusChanged(CaptureStatus.Failed);
            }
        }
    }

    private async Task ReadCaptureOutputAsync(Process process, CancellationToken cancellationToken)
    {
        try
        {
            while (!process.HasExited && !cancellationToken.IsCancellationRequested)
            {
                var line = await process.StandardOutput.ReadLineAsync(cancellationToken);
                if (line == null) break;

                // Parse packet data (simplified - in production, use proper XML parsing)
                if (line.Contains("<packet>", StringComparison.Ordinal) && _currentSession?.Status == CaptureStatus.Capturing)
                {
                    var packetData = new LivePacketData
                    {
                        SequenceNumber = Interlocked.Increment(ref _packetSequence),
                        Timestamp = DateTime.UtcNow,
                        InterfaceId = _currentSession.InterfaceName
                    };

                    // Update statistics
                    if (_currentSession != null)
                    {
                        _currentSession.Stats.TotalPackets++;
                        _currentSession.Stats.LastUpdate = DateTime.UtcNow;
                    }

                    OnPacketCaptured(packetData);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error reading capture output");
        }
    }

    private async Task MonitorStatisticsAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(1000, cancellationToken);

                if (_currentSession == null) continue;

                var now = DateTime.UtcNow;
                var elapsed = (now - _lastStatsUpdate).TotalSeconds;

                if (elapsed >= 1.0)
                {
                    var packetDelta = _currentSession.Stats.TotalPackets - _lastPacketCount;
                    var byteDelta = _currentSession.Stats.TotalBytes - _lastByteCount;

                    _currentSession.Stats.CurrentPacketsPerSecond = packetDelta / elapsed;
                    _currentSession.Stats.CurrentBytesPerSecond = byteDelta / elapsed;

                    _lastPacketCount = _currentSession.Stats.TotalPackets;
                    _lastByteCount = _currentSession.Stats.TotalBytes;
                    _lastStatsUpdate = now;

                    OnStatisticsUpdated(_currentSession.Stats);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error monitoring statistics");
            }
        }
    }

    private void OnPacketCaptured(LivePacketData packet)
    {
        PacketCaptured?.Invoke(this, packet);
    }

    private void OnStatisticsUpdated(CaptureSessionStats stats)
    {
        StatisticsUpdated?.Invoke(this, stats);
    }

    private void OnStatusChanged(CaptureStatus status)
    {
        StatusChanged?.Invoke(this, status);
    }

    private static string FindTSharkPath()
    {
        var paths = new[] { "tshark", @"C:\Program Files\Wireshark\tshark.exe", "/usr/bin/tshark", "/usr/local/bin/tshark" };
        return paths.FirstOrDefault(File.Exists) ?? "tshark";
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            // Dispose managed resources
            _captureCts?.Cancel();
            _captureProcess?.Kill(true);
            _captureProcess?.Dispose();
            _captureCts?.Dispose();
            _sessionLock.Dispose();
        }
        // Dispose unmanaged resources (if any) here
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}
