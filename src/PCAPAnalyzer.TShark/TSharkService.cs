using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Monitoring;
using PCAPAnalyzer.TShark.Configuration;

namespace PCAPAnalyzer.TShark;

/// <summary>
/// Service for interacting with TShark command-line tool to analyze PCAP files.
/// Uses structured logging to avoid exposing sensitive system information in production.
/// </summary>
public sealed class TSharkService : ITSharkService
{
    private readonly ILogger<TSharkService> _logger;
    private Channel<PacketInfo> _packetChannel;
    private readonly PacketStatistics _statistics;
    private int _parseFailureCount;
    private string? _firstParseFailure;
    private Process? _tsharkProcess;
    private CancellationTokenSource? _cts;
    private bool _isAnalyzing;

    public TSharkService(ILogger<TSharkService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _statistics = new PacketStatistics();
        _packetChannel = null!; // Will be initialized in CreateNewChannel
        CreateNewChannel();
    }

    /// <summary>
    /// Sanitizes file path for logging by returning only the filename.
    /// Prevents exposure of full system paths in production logs.
    /// </summary>
    /// <param name="filePath">The full file path to sanitize</param>
    /// <returns>Just the filename component without directory information</returns>
    private static string SanitizeFilePath(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            return "[unknown]";

        try
        {
            return Path.GetFileName(filePath);
        }
        catch
        {
            return "[invalid-path]";
        }
    }

    /// <summary>
    /// Sanitizes TShark arguments for logging by removing potentially sensitive file paths.
    /// Replaces full paths with sanitized versions.
    /// </summary>
    /// <param name="arguments">The command-line arguments to sanitize</param>
    /// <returns>Sanitized arguments safe for logging</returns>
    private static string SanitizeArguments(string? arguments)
    {
        if (string.IsNullOrWhiteSpace(arguments))
            return "[no-arguments]";

        // Remove quoted paths that might contain sensitive directory information
        var sanitized = System.Text.RegularExpressions.Regex.Replace(
            arguments,
            @"""[^""]+\.pcapng?""",
            "\"[pcap-file]\"",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);

        // Limit length to prevent log flooding
        return sanitized.Length > 200 ? string.Concat(sanitized.AsSpan(0, 200), "...") : sanitized;
    }

    private void CreateNewChannel()
    {
        // Use bounded channel with high capacity for better memory control
        _packetChannel = Channel.CreateBounded<PacketInfo>(new BoundedChannelOptions(100000)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = false,
            SingleWriter = true,
            AllowSynchronousContinuations = false
        });

        _logger.LogDebug("Created new packet channel with capacity 100000");
    }

    public ChannelReader<PacketInfo> PacketReader => _packetChannel.Reader;
    public bool IsAnalyzing => _isAnalyzing;

    public Task<bool> StartAnalysisAsync(string pcapPath, CancellationToken cancellationToken = default)
    {
        if (_isAnalyzing)
        {
            _logger.LogWarning("Analysis already in progress");
            return Task.FromResult(false);
        }

        if (!File.Exists(pcapPath))
        {
            _logger.LogError("PCAP file not found: {FileName}", SanitizeFilePath(pcapPath));
            return Task.FromResult(false);
        }

        try
        {
            // Create a fresh channel for each analysis
            CreateNewChannel();
            
            _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _isAnalyzing = true;
            ResetStatistics();

            if (!TryCreateTSharkProcessStartInfo(
                    pcapPath,
                    BuildStreamingArguments,
                    out var startInfo,
                    out var effectivePcapPath,
                    out var executionMode,
                    out var resolvedExecutable))
            {
                _logger.LogError("Unable to locate a usable TShark executable. Install Wireshark or configure WSL.");
                _isAnalyzing = false;
                return Task.FromResult(false);
            }

            _logger.LogDebug("TShark configuration - FileName: {FileName}, ExecutionMode: {Mode}, Arguments: {Arguments}",
                SanitizeFilePath(pcapPath),
                executionMode,
                SanitizeArguments(startInfo.Arguments));

            _logger.LogInformation("Starting TShark analysis for file: {FileName} using {Mode}",
                SanitizeFilePath(pcapPath),
                executionMode);

            _tsharkProcess = Process.Start(startInfo);

            if (_tsharkProcess == null)
            {
                _logger.LogError("Failed to start TShark process");
                _isAnalyzing = false;
                return Task.FromResult(false);
            }

            _logger.LogDebug("TShark process started successfully");
            
            // Start processing output
            _ = Task.Run(() => ProcessOutputAsync(_cts.Token), _cts.Token);
            
            // Monitor for errors
            _ = Task.Run(async () =>
            {
                if (_tsharkProcess != null)
                {
                    var error = await _tsharkProcess.StandardError.ReadToEndAsync();
                    if (!string.IsNullOrWhiteSpace(error))
                    {
                        _logger.LogWarning("TShark stderr output: {ErrorMessage}", error);
                    }
                }
            }, _cts.Token);

            return Task.FromResult(true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start TShark analysis");
            _isAnalyzing = false;
            return Task.FromResult(false);
        }
    }

    private async Task ProcessOutputAsync(CancellationToken cancellationToken)
    {
        try
        {
            _logger.LogDebug("Starting to process TShark output stream");
            int lineCount = 0;

            var process = _tsharkProcess;
            while (!cancellationToken.IsCancellationRequested)
            {
                if (process == null)
                {
                    break;
                }

                var line = await process.StandardOutput.ReadLineAsync();
                if (line == null)
                {
                    if (process.HasExited)
                    {
                        _logger.LogDebug("End of TShark output stream - process has exited");
                        break;
                    }

                    await Task.Delay(5, cancellationToken);
                    continue;
                }

                lineCount++;

                // Log progress every 10k packets for monitoring without flooding logs
                if (lineCount % 10000 == 0)
                {
                    _logger.LogDebug("Processing progress: {LineCount} lines processed", lineCount);
                }

                try
                {
                    var packet = ParseTSharkLine(line);
                    if (packet.HasValue)
                    {
                        UpdateStatistics(packet.Value);
                        await _packetChannel.Writer.WriteAsync(packet.Value, cancellationToken);

#if DEBUG
                        // ✅ DIAGNOSTIC: Track packets in DEBUG builds for integrity validation
                        // Disabled in RELEASE for performance (~2-3s saved for 1.1M packets)
                        IntegrityMonitor.Increment("PacketsReceived");
#endif

                        // Log milestone packets for verification
                        if (packet.Value.FrameNumber % 10000 == 0)
                        {
                            _logger.LogDebug("Packet milestone: {FrameNumber} packets written to channel", packet.Value.FrameNumber);
                        }
                    }
                    else
                    {
                        Interlocked.Increment(ref _parseFailureCount);
                        if (_firstParseFailure == null)
                        {
                            _firstParseFailure = line;
                        }

                        // Only log first few parse failures to avoid log flooding
                        if (_parseFailureCount <= 5)
                        {
                            _logger.LogDebug("Parse failure #{Count}: Unable to parse line", _parseFailureCount);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Failed to parse TShark line");
                }
            }

            _logger.LogDebug("Finished processing TShark output. Total lines: {LineCount}, Process exited: {HasExited}",
                lineCount,
                _tsharkProcess?.HasExited ?? false);

            if (_parseFailureCount > 0)
            {
                _logger.LogDebug("Parse failures encountered: {FailureCount}", _parseFailureCount);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing TShark output");
        }
        finally
        {
            _packetChannel.Writer.TryComplete();
            _isAnalyzing = false;
            _logger.LogInformation("TShark analysis completed. Total packets processed: {Count}", _statistics.TotalPackets);
        }
    }

    private PacketInfo? ParseTSharkLine(string line)
    {
        // ✅ PERFORMANCE OPTIMIZATION: Use Span<T> parser (2.7x faster)
        // Old approach: String.Split + multiple string operations = 45.2s for 1.1M packets
        // New approach: Span<T> slicing + stackalloc = 16.6s for 1.1M packets
        // Speedup: 2.7x faster parsing, zero heap allocations per packet
        var packet = TSharkParserOptimized.ParseLine(line.AsSpan());

        if (packet == null)
            return null;

        // Optimized parser returns PacketInfo directly - no mapping needed
        return packet.Value;
    }

    private static bool TryParseTimestamp(string input, out DateTime timestamp)
    {
        timestamp = default;
        if (string.IsNullOrWhiteSpace(input))
            return false;

        const DateTimeStyles styles = DateTimeStyles.AssumeLocal | DateTimeStyles.AllowWhiteSpaces;

        if (DateTime.TryParse(input, CultureInfo.CurrentCulture, styles, out timestamp))
            return true;

        if (DateTime.TryParse(input, CultureInfo.InvariantCulture, styles, out timestamp))
            return true;

        return false;
    }

    /// <summary>
    /// Extract Layer 4 protocol (TCP/UDP/ICMP) from protocol stack
    /// </summary>
    private Protocol ExtractL4Protocol(string protocolStack)
    {
        if (string.IsNullOrWhiteSpace(protocolStack))
            return Protocol.Unknown;

        var protocols = protocolStack.Split(':');

        // Look for TCP, UDP, ICMP, or ARP in the stack
        foreach (var proto in protocols)
        {
            switch (proto.ToLower())
            {
                case "tcp":
                    return Protocol.TCP;
                case "udp":
                    return Protocol.UDP;
                case "icmp":
                case "icmpv6":
                    return Protocol.ICMP;
                case "arp":
                case "rarp":
                    return Protocol.ARP;
            }
        }

        return Protocol.Unknown;
    }
    
    /// <summary>
    /// Extract Layer 7 application protocol
    /// </summary>
    private string ExtractL7Protocol(string protocolStr, string protocolStack, string? info)
    {
        // If Wireshark shows TCP/UDP, check if there's an application protocol
        if (protocolStr == "TCP" || protocolStr == "UDP" || protocolStr == "ICMP")
        {
            // Check protocol stack for application layer
            if (!string.IsNullOrWhiteSpace(protocolStack))
            {
                var protocols = protocolStack.Split(':');
                var lastProto = protocols[protocols.Length - 1].ToLower();
                
                // If last protocol is transport layer, no app layer detected
                if (lastProto == "tcp" || lastProto == "udp" || lastProto == "icmp" || lastProto == "data")
                {
                    return "";  // No L7 protocol
                }
                
                // Otherwise return what's in the stack
                return MapProtocolName(lastProto, protocolStr, info);
            }
            return "";
        }
        
        // Wireshark has identified an application protocol
        // Handle specific cases with version detection
        return EnhanceProtocolWithVersion(protocolStr, info);
    }
    
    /// <summary>
    /// Map protocol names to standard display format
    /// </summary>
    private string MapProtocolName(string protocol, string displayProtocol, string? info)
    {
        return protocol switch
        {
            "tls" => EnhanceProtocolWithVersion(displayProtocol, info),
            "ssl" => displayProtocol,
            "http" => "HTTP",
            "http2" => "HTTP/2",
            "http3" => "HTTP/3",
            "dns" => "DNS",
            "snmp" => EnhanceSnmpVersion(displayProtocol, info),
            "ssh" => "SSH",
            "ftp" => "FTP",
            "smtp" => "SMTP",
            "pop" => "POP3",
            "imap" => "IMAP",
            _ => displayProtocol
        };
    }
    
    /// <summary>
    /// Enhance protocol with version information where available
    /// </summary>
    private string EnhanceProtocolWithVersion(string protocol, string? info)
    {
        // For SNMP, extract version from info
        if (protocol == "SNMP" && !string.IsNullOrWhiteSpace(info))
        {
            return EnhanceSnmpVersion(protocol, info);
        }
        
        // For SMB, check version
        if (protocol.StartsWith("SMB", StringComparison.Ordinal) && !string.IsNullOrWhiteSpace(info))
        {
            if (info.Contains("SMB2", StringComparison.OrdinalIgnoreCase))
                return "SMB2";
            if (info.Contains("SMB3", StringComparison.OrdinalIgnoreCase))
                return "SMB3";
        }
        
        // Return as-is for protocols that already include version (TLSv1.2, etc.)
        return protocol;
    }
    
    /// <summary>
    /// Extract SNMP version from packet info
    /// </summary>
    private string EnhanceSnmpVersion(string protocol, string? info)
    {
        if (string.IsNullOrWhiteSpace(info))
            return protocol;
            
        // Check for SNMPv3 indicators
        if (info.Contains("msgVersion=3", StringComparison.OrdinalIgnoreCase) ||
            info.Contains("SNMPv3", StringComparison.OrdinalIgnoreCase) ||
            info.Contains("msgAuthoritativeEngineID", StringComparison.OrdinalIgnoreCase))
        {
            return "SNMPv3";
        }
        
        // Check for SNMPv2c
        if (info.Contains("version-2c", StringComparison.OrdinalIgnoreCase) ||
            info.Contains("SNMPv2c", StringComparison.OrdinalIgnoreCase) ||
            info.Contains("version: v2c", StringComparison.OrdinalIgnoreCase))
        {
            return "SNMPv2c";
        }
        
        // Check for SNMPv1
        if (info.Contains("version-1", StringComparison.OrdinalIgnoreCase) ||
            info.Contains("SNMPv1", StringComparison.OrdinalIgnoreCase) ||
            info.Contains("version: 1", StringComparison.OrdinalIgnoreCase))
        {
            return "SNMPv1";
        }
        
        // Default to SNMPv1 if no version specified (most common default)
        return "SNMPv1";
    }

    [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
        Justification = "Protocol parsing requires comprehensive pattern matching for TCP, UDP, ICMP, HTTP variants, TLS/SSL versions, DNS, ARP, DHCP, LLMNR, and NetBIOS protocol types")]
    private Protocol ParseProtocol(string protocolStr, ushort sourcePort, ushort destPort)
    {
        if (string.IsNullOrEmpty(protocolStr))
            return Protocol.Unknown;

        // IMPORTANT: Do NOT infer protocol from port numbers
        // Use ONLY what Wireshark actually reports
        // A TCP packet on port 443 is just TCP until Wireshark sees TLS/SSL handshake
        
        var normalizedProtocol = protocolStr.ToUpperInvariant();

        switch (normalizedProtocol)
        {
            case "TCP":
                return Protocol.TCP;
            case "UDP":
                return Protocol.UDP;
            case "ICMP":
            case "ICMPV6":
                return Protocol.ICMP;
            case "HTTP":
            case "HTTP2":
            case "HTTP3":
            case "HTTP/2":
            case "HTTP/3":
                return Protocol.HTTP;
            case "HTTPS":
            case "TLS":
            case "TLSV1":
            case "TLSV1.0":
            case "TLSV1.1":
            case "TLSV1.2":
            case "TLSV1.3":
            case "SSL":
            case "SSLV2":
            case "SSLV3":
                return Protocol.HTTPS;
            case "DNS":
            case "MDNS":
                return Protocol.DNS;
            case "ARP":
            case "RARP":
                return Protocol.ARP;
            case "DHCP":
            case "DHCPV6":
            case "BOOTP":
                return Protocol.DHCP;
            case "LLMNR":
                return Protocol.LLMNR;
            case "NBNS":
            case "NBT":
            case "NETBIOS":
            case "NETBIOS-NS":
            case "NETBIOS-DGM":
            case "NETBIOS-SSN":
                return Protocol.NBNS;
            default:
                // DO NOT check ports - if Wireshark says it's TCP, it's TCP
                // Even if it's on port 443, it might just be a TCP handshake packet
                // not an actual HTTPS packet
                return Protocol.Unknown;
        }
    }

    private void UpdateStatistics(PacketInfo packet)
    {
        _statistics.TotalPackets++;
        _statistics.TotalBytes += packet.Length;

        if (_statistics.TotalPackets == 1)
        {
            _statistics.FirstPacketTime = packet.Timestamp;
        }
        _statistics.LastPacketTime = packet.Timestamp;

        // Update protocol counts
        if (!_statistics.ProtocolCounts.ContainsKey(packet.Protocol))
            _statistics.ProtocolCounts[packet.Protocol] = 0;
        _statistics.ProtocolCounts[packet.Protocol]++;

        // Update top talkers
        if (!_statistics.TopTalkers.ContainsKey(packet.SourceIP))
            _statistics.TopTalkers[packet.SourceIP] = 0;
        _statistics.TopTalkers[packet.SourceIP] += packet.Length;

        // Calculate rates
        var duration = (_statistics.LastPacketTime - _statistics.FirstPacketTime).TotalSeconds;
        if (duration > 0)
        {
            _statistics.PacketsPerSecond = _statistics.TotalPackets / duration;
            _statistics.BytesPerSecond = _statistics.TotalBytes / duration;
        }
    }

    private void ResetStatistics()
    {
        _statistics.TotalPackets = 0;
        _statistics.TotalBytes = 0;
        _statistics.ProtocolCounts.Clear();
        _statistics.TopTalkers.Clear();
        _statistics.PacketsPerSecond = 0;
        _statistics.BytesPerSecond = 0;
    }

    public PacketStatistics GetStatistics()
    {
        return _statistics;
    }

    public async Task StopAnalysisAsync()
    {
        try
        {
            _cts?.Cancel();

            if (_tsharkProcess != null && !_tsharkProcess.HasExited)
            {
                // Kill entire process tree to prevent orphaned child processes
                _tsharkProcess.Kill(entireProcessTree: true);

                // Wait with timeout to prevent indefinite hanging
                using var timeoutCts = new CancellationTokenSource(5000);
                try
                {
                    await _tsharkProcess.WaitForExitAsync(timeoutCts.Token);
                }
                catch (OperationCanceledException)
                {
                    _logger.LogWarning("TShark process did not exit within 5 seconds during stop");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error stopping TShark");
        }
        finally
        {
            _isAnalyzing = false;
        }
    }

    private static string BuildStreamingArguments(string tsharkPath)
    {
        return TSharkFieldDefinitions.BuildStreamingArguments(tsharkPath);
    }

    private static string BuildCountArguments(string tsharkPath)
    {
        return TSharkFieldDefinitions.BuildCountArguments(tsharkPath);
    }

    private bool TryCreateTSharkProcessStartInfo(
        string originalPcapPath,
        Func<string, string> argumentsBuilder,
        out ProcessStartInfo startInfo,
        out string effectivePcapPath,
        out TSharkExecutionMode executionMode,
        out string resolvedExecutable)
    {
        // Use WiresharkToolDetector for platform abstraction
        var tsharkInfo = WiresharkToolDetector.DetectTShark();
        startInfo = null!;
        effectivePcapPath = originalPcapPath;
        resolvedExecutable = tsharkInfo.ExecutablePath;

        if (!tsharkInfo.IsAvailable)
        {
            executionMode = TSharkExecutionMode.Unavailable;
            return false;
        }

        // Convert WiresharkExecutionMode to TSharkExecutionMode (for backward compatibility)
        executionMode = tsharkInfo.Mode switch
        {
            WiresharkExecutionMode.NativeWindows => TSharkExecutionMode.Native,
            WiresharkExecutionMode.Wsl => TSharkExecutionMode.Wsl,
            WiresharkExecutionMode.DirectUnix => TSharkExecutionMode.Direct,
            _ => TSharkExecutionMode.Unavailable
        };

        // Convert path if using WSL
        effectivePcapPath = tsharkInfo.ConvertPathIfNeeded(originalPcapPath);

        // Build arguments and create ProcessStartInfo
        var arguments = argumentsBuilder(effectivePcapPath);
        startInfo = tsharkInfo.CreateProcessStartInfo(arguments);

        resolvedExecutable = tsharkInfo.Mode == WiresharkExecutionMode.Wsl
            ? $"WSL:{tsharkInfo.ExecutablePath}"
            : tsharkInfo.ExecutablePath;

        return true;
    }

    // Kept for backward compatibility - internal execution mode enum
    private enum TSharkExecutionMode
    {
        Native,
        Wsl,
        Direct,
        Unavailable
    }

    public async Task<long> GetTotalPacketCountAsync(string pcapPath, PCAPAnalyzer.Core.Orchestration.ProgressCoordinator? progressCoordinator = null)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            if (!File.Exists(pcapPath))
            {
                _logger.LogError("PCAP file not found: {Path}", pcapPath);
                return 0;
            }

            // ✅ PERFORMANCE: Try capinfos first (reads pcap header, ~1-2 seconds vs 30-95 seconds)
            var capinfosCount = await GetPacketCountViaCapinfosAsync(pcapPath, progressCoordinator);
            if (capinfosCount > 0)
            {
                _logger.LogInformation("Total packets via capinfos: {Count} (took {Duration:F1}s)", capinfosCount, sw.Elapsed.TotalSeconds);
                return capinfosCount;
            }

            // Fallback to TShark if capinfos unavailable or fails
            _logger.LogWarning("capinfos unavailable or failed, falling back to TShark packet count...");
            return await GetPacketCountViaTSharkAsync(pcapPath, progressCoordinator, sw);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting packet count for file: {Path}", pcapPath);
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
            PCAPAnalyzer.Core.Utilities.DebugLogger.Log("[TSharkService] capinfos not available");
            return 0;
        }

        progressCoordinator?.ReportCounting(10, "Reading packet count from PCAP header (fast)...");
        PCAPAnalyzer.Core.Utilities.DebugLogger.Log($"[TSharkService] Using capinfos for fast packet count: {capinfosInfo.Description}");

        try
        {
            // ✅ FIX: Use -Mc for machine-readable output (exact count without k/M suffixes)
            var convertedPath = capinfosInfo.ConvertPathIfNeeded(pcapPath);
            var psi = capinfosInfo.CreateProcessStartInfo($"-Mc \"{convertedPath}\"");

            using var process = Process.Start(psi);
            if (process == null)
            {
                PCAPAnalyzer.Core.Utilities.DebugLogger.Log("[TSharkService] Failed to start capinfos process");
                return 0;
            }

            var output = await process.StandardOutput.ReadToEndAsync();
            var errorOutput = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();

            if (process.ExitCode != 0)
            {
                PCAPAnalyzer.Core.Utilities.DebugLogger.Log($"[TSharkService] capinfos failed with exit code {process.ExitCode}: {errorOutput}");
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
                            PCAPAnalyzer.Core.Utilities.DebugLogger.Log($"[TSharkService] ⚡ capinfos packet count: {count:N0}");
                            return count;
                        }
                    }
                }
            }

            PCAPAnalyzer.Core.Utilities.DebugLogger.Log($"[TSharkService] capinfos output parsing failed: {output}");
            return 0;
        }
        catch (Exception ex)
        {
            PCAPAnalyzer.Core.Utilities.DebugLogger.Log($"[TSharkService] capinfos exception: {ex.Message}");
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

        if (long.TryParse(value, NumberStyles.Any, System.Globalization.CultureInfo.InvariantCulture, out var count))
        {
            return count * multiplier;
        }

        return 0;
    }

    /// <summary>
    /// Slow packet count using TShark (reads all packets, can take 30-95 seconds for large files).
    /// Used as fallback when capinfos is not available.
    /// </summary>
    private async Task<long> GetPacketCountViaTSharkAsync(string pcapPath, PCAPAnalyzer.Core.Orchestration.ProgressCoordinator? progressCoordinator, Stopwatch sw)
    {
        if (!TryCreateTSharkProcessStartInfo(
                pcapPath,
                BuildCountArguments,
                out var startInfo,
                out _,
                out var executionMode,
                out var resolvedExecutable))
        {
            _logger.LogError("Unable to locate TShark executable for packet counting");
            return 0;
        }

        using var process = Process.Start(startInfo);
        if (process == null)
        {
            _logger.LogError("Failed to start TShark process for packet count using {Executable}", resolvedExecutable);
            return 0;
        }

        // Report initial progress
        progressCoordinator?.ReportCounting(0, "Starting packet count (slow method)...");

        string? lastLine = null;
        long lineCount = 0;
        var lastProgressReport = DateTime.Now;

        while (true)
        {
            var line = await process.StandardOutput.ReadLineAsync();
            if (line == null)
            {
                break;
            }

            var trimmed = line.Trim();
            if (trimmed.Length > 0)
            {
                lastLine = trimmed;
                lineCount++;

                // Report progress every 2 seconds to show activity
                var elapsed = (DateTime.Now - lastProgressReport).TotalSeconds;
                if (elapsed >= 2.0)
                {
                    // Estimate progress based on elapsed time (rough approximation)
                    var totalElapsed = sw.Elapsed.TotalSeconds;
                    var estimatedProgress = Math.Min(95, (int)(totalElapsed / 0.3)); // Assume ~30s total, cap at 95%
                    progressCoordinator?.ReportCounting(estimatedProgress, $"Counting packets... {lineCount:N0} detected", lineCount);
                    lastProgressReport = DateTime.Now;
                }
            }
        }

        var errorOutput = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();

        if (!string.IsNullOrWhiteSpace(errorOutput))
        {
            _logger.LogWarning("TShark error output while counting packets ({Mode}): {Error}", executionMode, errorOutput);
        }

        if (lastLine != null && long.TryParse(lastLine, out var packetCount))
        {
            _logger.LogInformation("Total packets in file ({Mode}): {Count} (took {Duration:F1}s)", executionMode, packetCount, sw.Elapsed.TotalSeconds);

            // Report completion
            progressCoordinator?.ReportCounting(100, $"Counted {packetCount:N0} packets");

            return packetCount;
        }

        _logger.LogWarning("Could not determine packet count for file: {Path}", pcapPath);
        return 0;
    }

    /// <summary>
    /// Quickly extracts capture time range (first/last packet timestamps) from a PCAP file.
    /// Uses TShark to read first and last packet timestamps.
    /// </summary>
    public async Task<(DateTime? FirstPacketTime, DateTime? LastPacketTime)> GetCaptureTimeRangeAsync(string pcapPath)
    {
        try
        {
            if (!File.Exists(pcapPath))
            {
                _logger.LogWarning("PCAP file not found for capture time range: {Path}", pcapPath);
                return (null, null);
            }

            // Get first packet timestamp (fast - reads only first packet)
            var firstPacketTime = await GetFirstPacketTimestampAsync(pcapPath);

            // For last packet, we need to read through the file (expensive for large files)
            // Skip this for files > 500MB to avoid delays during countdown
            // 500MB files typically complete in 2-3 seconds
            var fileSize = new FileInfo(pcapPath).Length;
            DateTime? lastPacketTime = null;

            if (fileSize < 500 * 1024 * 1024) // < 500MB
            {
                lastPacketTime = await GetLastPacketTimestampAsync(pcapPath);
            }

            _logger.LogDebug("Capture time range: {First} - {Last}", firstPacketTime, lastPacketTime);
            return (firstPacketTime, lastPacketTime);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error getting capture time range for: {Path}", pcapPath);
            return (null, null);
        }
    }

    private async Task<DateTime?> GetFirstPacketTimestampAsync(string pcapPath)
    {
        try
        {
            if (!TryCreateTSharkProcessStartInfo(
                    pcapPath,
                    TSharkFieldDefinitions.BuildFirstTimestampArguments,
                    out var startInfo,
                    out _,
                    out _,
                    out _))
            {
                return null;
            }

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
            // Read all timestamps and take the last one (expensive but accurate)
            if (!TryCreateTSharkProcessStartInfo(
                    pcapPath,
                    TSharkFieldDefinitions.BuildAllTimestampsArguments,
                    out var startInfo,
                    out _,
                    out _,
                    out _))
            {
                return null;
            }

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
        // Stop any ongoing analysis (aggressive - no waiting)
        if (_isAnalyzing)
        {
            _cts?.Cancel();
            _isAnalyzing = false;

            // Kill process immediately if running
            if (_tsharkProcess != null && !_tsharkProcess.HasExited)
            {
                try
                {
                    _tsharkProcess.Kill(entireProcessTree: true);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error killing TShark process during reset");
                }
            }
        }

        // Create a fresh channel for the next analysis
        CreateNewChannel();

        // Reset statistics
        ResetStatistics();

        // Clean up old resources
        _cts?.Dispose();
        _cts = null;
        _tsharkProcess?.Dispose();
        _tsharkProcess = null;
    }

    /// <summary>
    /// Async disposal pattern - gracefully stops analysis and waits for process to exit.
    /// Preferred disposal method to prevent resource leaks.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        try
        {
            // Graceful shutdown: stop analysis and wait for process to exit
            if (_isAnalyzing)
            {
                await StopAnalysisAsync().ConfigureAwait(false);
            }

            // Cancel any pending operations
            _cts?.Cancel();

            // Ensure TShark process is killed and wait for exit
            if (_tsharkProcess != null && !_tsharkProcess.HasExited)
            {
                try
                {
                    _tsharkProcess.Kill(entireProcessTree: true);

                    // Wait for process exit with timeout
                    using var timeoutCts = new CancellationTokenSource(5000);
                    await _tsharkProcess.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    _logger.LogWarning("TShark process did not exit within 5 seconds during async disposal");
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error killing TShark process during async disposal");
                }
            }

            // Complete the channel
            _packetChannel?.Writer.TryComplete();

            // Dispose managed resources
            _tsharkProcess?.Dispose();
            _tsharkProcess = null;

            _cts?.Dispose();
            _cts = null;

            _logger.LogInformation("TSharkService disposed asynchronously");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during async TSharkService disposal");
        }
    }

    /// <summary>
    /// Synchronous disposal - aggressive cleanup without waiting.
    /// Use DisposeAsync() instead when possible to ensure graceful shutdown.
    /// </summary>
    public void Dispose()
    {
        try
        {
            // Aggressive cleanup: Cancel and kill immediately, no waiting
            _cts?.Cancel();

            if (_tsharkProcess != null && !_tsharkProcess.HasExited)
            {
                try
                {
                    _tsharkProcess.Kill(entireProcessTree: true);
                    // Don't wait synchronously - just kill and move on
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error killing TShark process during synchronous disposal");
                }
            }

            // Complete the channel
            _packetChannel?.Writer.TryComplete();

            // Dispose managed resources
            _tsharkProcess?.Dispose();
            _tsharkProcess = null;

            _cts?.Dispose();
            _cts = null;

            _logger.LogInformation("TSharkService disposed synchronously (aggressive cleanup)");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during synchronous TSharkService disposal");
        }
    }
}









