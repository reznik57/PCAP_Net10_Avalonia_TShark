using System;
using System.Runtime.CompilerServices;

namespace PCAPAnalyzer.Core.Utilities;

/// <summary>
/// Conditional debug logging utility - logs only when PCAP_DEBUG environment variable is set.
/// Prevents console flooding in production while allowing diagnostics during development.
///
/// Performance: Uses AggressiveInlining to allow JIT to eliminate dead code when disabled.
/// </summary>
public static class DebugLogger
{
    private static readonly bool _isDebugEnabled = InitializeDebugMode();

    private static bool InitializeDebugMode()
    {
        var debugEnv = Environment.GetEnvironmentVariable("PCAP_DEBUG");
        var isEnabled = string.Equals(debugEnv, "1", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(debugEnv, "true", StringComparison.OrdinalIgnoreCase);

        if (isEnabled)
        {
            Console.WriteLine("[DebugLogger] Debug logging ENABLED (set PCAP_DEBUG=0 to disable)");
        }

        return isEnabled;
    }

    /// <summary>
    /// Returns true if debug logging is currently enabled.
    /// Check this before building expensive log messages to avoid allocation overhead.
    /// </summary>
    public static bool IsEnabled
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => _isDebugEnabled;
    }

    /// <summary>
    /// Logs a debug message if debug mode is enabled.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Log(string message)
    {
        if (_isDebugEnabled)
        {
            Console.WriteLine(message);
        }
    }

    /// <summary>
    /// Logs using a message factory delegate - avoids string allocation when logging is disabled.
    /// Use for hot paths where string interpolation overhead matters.
    /// Example: DebugLogger.Log(() => $"Processed {count} packets");
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Log(Func<string> messageFactory)
    {
        if (_isDebugEnabled)
        {
            Console.WriteLine(messageFactory());
        }
    }

    /// <summary>
    /// Logs a formatted debug message if debug mode is enabled.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Log(string format, params object?[] args)
    {
        if (_isDebugEnabled)
        {
            Console.WriteLine(format, args);
        }
    }

    /// <summary>
    /// Logs a critical message (always shown, regardless of debug setting).
    /// Use for errors, warnings, and important status updates.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Critical(string message)
    {
        Console.WriteLine(message);
    }

    /// <summary>
    /// Logs a critical formatted message (always shown).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Critical(string format, params object?[] args)
    {
        Console.WriteLine(format, args);
    }
}
