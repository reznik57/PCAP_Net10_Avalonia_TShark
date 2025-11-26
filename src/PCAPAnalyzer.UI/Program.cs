using Avalonia;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.TShark;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI;

public static class Program
{
    // Windows API for console allocation
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [System.Runtime.InteropServices.DefaultDllImportSearchPaths(System.Runtime.InteropServices.DllImportSearchPath.System32)]
    private static extern bool AllocConsole();

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [System.Runtime.InteropServices.DefaultDllImportSearchPaths(System.Runtime.InteropServices.DllImportSearchPath.System32)]
    private static extern bool AttachConsole(int processId);
    
    private const int ATTACH_PARENT_PROCESS = -1;
    
    // Initialization code. Don't use any Avalonia, third-party APIs or any
    // SynchronizationContext-reliant code before AppMain is called: things aren't initialized
    // yet and stuff might break.
    [STAThread]
    public static void Main(string[] args)
    {
        // Try to attach to parent console or allocate a new one (Windows only)
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // First try to attach to parent process console
            if (!AttachConsole(ATTACH_PARENT_PROCESS))
            {
                // If that fails, allocate a new console
                AllocConsole();
            }
            
            // Redirect standard output to console
            Console.SetOut(new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
            Console.SetError(new StreamWriter(Console.OpenStandardError()) { AutoFlush = true });
        }
        
        // Set up global exception handlers FIRST
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
        
        try
        {
            DebugLogger.Log("[PCAPAnalyzer] Starting application...");
            DebugLogger.Log("[PCAPAnalyzer] Exception handlers registered");
            DebugLogger.Log($"[PCAPAnalyzer] .NET Version: {Environment.Version}");
            DebugLogger.Log($"[PCAPAnalyzer] OS: {Environment.OSVersion}");
            DebugLogger.Log($"[PCAPAnalyzer] Current Directory: {Environment.CurrentDirectory}");
            
            // Check for command-line mode
            if (args.Length > 0 && File.Exists(args[0]) && args[0].EndsWith(".pcap", StringComparison.OrdinalIgnoreCase))
            {
                DebugLogger.Log($"[PCAPAnalyzer] Command-line mode: {args[0]}");
                RunCommandLineAnalysis(args[0]).GetAwaiter().GetResult();
                return;
            }
            
            // Check if we're in a GUI-capable environment
            var display = Environment.GetEnvironmentVariable("DISPLAY");
            DebugLogger.Log($"[PCAPAnalyzer] DISPLAY environment variable: {display ?? "(not set)"}");
            
            // Try to build and start Avalonia
            DebugLogger.Log("[PCAPAnalyzer] Building Avalonia app...");
            var app = BuildAvaloniaApp();
            
            DebugLogger.Log("[PCAPAnalyzer] Starting with classic desktop lifetime...");

            try
            {
                app.StartWithClassicDesktopLifetime(args);
                DebugLogger.Log("[PCAPAnalyzer] Application exited normally");
            }
            catch (Exception avaloniaEx)
            {
                // Capture Avalonia-specific exceptions
                DebugLogger.Critical($"[PCAPAnalyzer] ⚠️ AVALONIA EXCEPTION: {avaloniaEx.GetType().FullName}");
                DebugLogger.Critical($"[PCAPAnalyzer] Message: {avaloniaEx.Message}");
                DebugLogger.Critical($"[PCAPAnalyzer] Stack Trace:\n{avaloniaEx.StackTrace}");

                if (avaloniaEx.InnerException != null)
                {
                    DebugLogger.Critical($"[PCAPAnalyzer] Inner Exception: {avaloniaEx.InnerException.GetType().FullName}");
                    DebugLogger.Critical($"[PCAPAnalyzer] Inner Message: {avaloniaEx.InnerException.Message}");
                    DebugLogger.Critical($"[PCAPAnalyzer] Inner Stack:\n{avaloniaEx.InnerException.StackTrace}");
                }

                // Write to error log file
                var errorLog = Path.Combine(Environment.CurrentDirectory, "pcap_crash.log");
                File.WriteAllText(errorLog, $@"
PCAP Analyzer Crash Report
==========================
Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}
Exception: {avaloniaEx.GetType().FullName}
Message: {avaloniaEx.Message}

Stack Trace:
{avaloniaEx.StackTrace}

Inner Exception: {avaloniaEx.InnerException?.GetType().FullName}
Inner Message: {avaloniaEx.InnerException?.Message}
Inner Stack:
{avaloniaEx.InnerException?.StackTrace}
");

                Console.WriteLine($"\n\n⚠️⚠️⚠️ CRASH DETAILS WRITTEN TO: {errorLog} ⚠️⚠️⚠️\n");
                throw;
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[PCAPAnalyzer] FATAL ERROR: {ex.GetType().Name}");
            DebugLogger.Log($"[PCAPAnalyzer] Message: {ex.Message}");
            DebugLogger.Log($"[PCAPAnalyzer] Stack Trace:\n{ex.StackTrace}");
            
            if (ex.InnerException != null)
            {
                DebugLogger.Log($"[PCAPAnalyzer] Inner Exception: {ex.InnerException.GetType().Name}");
                DebugLogger.Log($"[PCAPAnalyzer] Inner Message: {ex.InnerException.Message}");
                DebugLogger.Log($"[PCAPAnalyzer] Inner Stack Trace:\n{ex.InnerException.StackTrace}");
            }
            
            Environment.Exit(-1);
        }
    }
    
    // Command-line analysis mode for testing performance
    private static async Task RunCommandLineAnalysis(string pcapFile)
    {
        DebugLogger.Log("[CLI] Running command-line analysis");
        DebugLogger.Log($"[CLI] File: {pcapFile}");
        
        var fileInfo = new FileInfo(pcapFile);
        DebugLogger.Log($"[CLI] Size: {fileInfo.Length / 1024.0 / 1024.0:F2} MB");
        
        try
        {
            var tsharkService = new TSharkService(NullLogger<TSharkService>.Instance);
            var cts = new CancellationTokenSource();
            
            // Get total packet count
            DebugLogger.Log("[CLI] Getting packet count...");
            var totalPackets = await tsharkService.GetTotalPacketCountAsync(pcapFile);
            DebugLogger.Log($"[CLI] Total packets in file: {totalPackets:N0}");
            
            // Start analysis
            DebugLogger.Log("[CLI] Starting analysis...");
            var success = await tsharkService.StartAnalysisAsync(pcapFile, cts.Token);
            if (!success)
            {
                DebugLogger.Log("[CLI] Failed to start TShark analysis");
                return;
            }
            
            var stopwatch = Stopwatch.StartNew();
            var packetCount = 0;
            var totalBytes = 0L;
            var reader = tsharkService.PacketReader;
            
            DebugLogger.Log("[CLI] Processing packets...");
            
            await foreach (var packet in reader.ReadAllAsync(cts.Token))
            {
                packetCount++;
                totalBytes += packet.Length;
                
                // Progress update every 1000 packets
                if (packetCount % 1000 == 0)
                {
                    var elapsed = stopwatch.Elapsed.TotalSeconds;
                    var rate = elapsed > 0 ? packetCount / elapsed : 0;
                    var mbps = elapsed > 0 ? (totalBytes / 1024.0 / 1024.0) / elapsed : 0;
                    DebugLogger.Log($"[PROGRESS] {packetCount:N0} packets @ {rate:N0} pkt/s ({mbps:F2} MB/s)");
                }
                
                // Stop if we've processed all packets
                if (totalPackets > 0 && packetCount >= totalPackets)
                    break;
            }
            
            stopwatch.Stop();
            
            // Final statistics
            var finalRate = stopwatch.Elapsed.TotalSeconds > 0 ? packetCount / stopwatch.Elapsed.TotalSeconds : 0;
            var finalMbps = stopwatch.Elapsed.TotalSeconds > 0 ? (totalBytes / 1024.0 / 1024.0) / stopwatch.Elapsed.TotalSeconds : 0;
            
            DebugLogger.Log("");
            DebugLogger.Log("=====================================");
            DebugLogger.Log("Analysis Complete");
            DebugLogger.Log("=====================================");
            DebugLogger.Log($"File: {Path.GetFileName(pcapFile)}");
            DebugLogger.Log($"Total Packets: {packetCount:N0}");
            DebugLogger.Log($"Total Data: {totalBytes / 1024.0 / 1024.0:F2} MB");
            DebugLogger.Log($"Duration: {stopwatch.Elapsed.TotalSeconds:F2} seconds");
            DebugLogger.Log($"Processing Rate: {finalRate:N0} packets/second");
            DebugLogger.Log($"Throughput: {finalMbps:F2} MB/second");
            DebugLogger.Log("");
            
            // Performance assessment
            if (finalRate >= 20000)
            {
                DebugLogger.Log("[SUCCESS] Achieved target performance (>20,000 pkt/s)");
            }
            else if (finalRate >= 15000)
            {
                DebugLogger.Log($"[GOOD] Good performance: {finalRate:N0} pkt/s");
            }
            else
            {
                DebugLogger.Log($"[INFO] Performance: {finalRate:N0} pkt/s (Target: 20,000 pkt/s)");
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[ERROR] Analysis failed: {ex.Message}");
            DebugLogger.Log($"[ERROR] Stack trace: {ex.StackTrace}");
        }
    }

    private static void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        var ex = e.ExceptionObject as Exception;
        DebugLogger.Log($"[PCAPAnalyzer] UNHANDLED EXCEPTION: {ex?.GetType().Name ?? "Unknown"}");
        DebugLogger.Log($"[PCAPAnalyzer] Message: {ex?.Message ?? "No message"}");
        DebugLogger.Log($"[PCAPAnalyzer] Stack Trace:\n{ex?.StackTrace ?? "No stack trace"}");
        DebugLogger.Log($"[PCAPAnalyzer] Is Terminating: {e.IsTerminating}");
    }

    private static void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        DebugLogger.Log($"[PCAPAnalyzer] UNOBSERVED TASK EXCEPTION: {e.Exception.GetType().Name}");
        DebugLogger.Log($"[PCAPAnalyzer] Message: {e.Exception.Message}");
        DebugLogger.Log($"[PCAPAnalyzer] Stack Trace:\n{e.Exception.StackTrace}");
        
        // Mark as observed to prevent app termination
        e.SetObserved();
    }

    // Avalonia configuration, don't remove; also used by visual designer.
    public static AppBuilder BuildAvaloniaApp()
    {
        try
        {
            DebugLogger.Log("[PCAPAnalyzer] Configuring Avalonia...");
            
            var builder = AppBuilder.Configure<App>();
            DebugLogger.Log("[PCAPAnalyzer] App configured");
            
            builder = builder.UsePlatformDetect();
            DebugLogger.Log("[PCAPAnalyzer] Platform detection configured");
            
            builder = builder.WithInterFont();
            DebugLogger.Log("[PCAPAnalyzer] Inter font configured");
            
            builder = builder.LogToTrace();
            DebugLogger.Log("[PCAPAnalyzer] Logging configured");
            
            return builder;
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[PCAPAnalyzer] Error in BuildAvaloniaApp: {ex.Message}");
            throw;
        }
    }
}
