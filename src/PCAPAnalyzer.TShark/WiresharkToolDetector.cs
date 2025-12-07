using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Runtime.InteropServices;

namespace PCAPAnalyzer.TShark;

/// <summary>
/// Execution mode for Wireshark tools
/// </summary>
public enum WiresharkExecutionMode
{
    /// <summary>Tool not available on system</summary>
    Unavailable,
    /// <summary>Native Windows executable in PATH or Wireshark installation</summary>
    NativeWindows,
    /// <summary>WSL wrapper (wsl.exe tshark/editcap)</summary>
    Wsl,
    /// <summary>Direct Linux/Mac executable</summary>
    DirectUnix
}

/// <summary>
/// Tool detection result with execution details
/// </summary>
public sealed class WiresharkToolInfo
{
    public bool IsAvailable { get; init; }
    public WiresharkExecutionMode Mode { get; init; }
    public string ExecutablePath { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;

    /// <summary>
    /// Creates ProcessStartInfo for the tool with given arguments.
    /// SECURITY: Uses ArgumentList to prevent command injection.
    /// </summary>
    /// <param name="arguments">Array of individual arguments (NOT a shell command string)</param>
    public ProcessStartInfo CreateProcessStartInfo(params string[] arguments)
    {
        var psi = new ProcessStartInfo
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = System.Text.Encoding.UTF8,
            StandardErrorEncoding = System.Text.Encoding.UTF8
        };

        if (Mode == WiresharkExecutionMode.Wsl)
        {
            psi.FileName = "wsl.exe";
            // SECURITY: Use ArgumentList - each argument is properly escaped by .NET
            psi.ArgumentList.Add(ExecutablePath);
            foreach (var arg in arguments)
            {
                psi.ArgumentList.Add(arg);
            }
        }
        else
        {
            psi.FileName = ExecutablePath;
            // SECURITY: Use ArgumentList - each argument is properly escaped by .NET
            foreach (var arg in arguments)
            {
                psi.ArgumentList.Add(arg);
            }
        }

        return psi;
    }

    /// <summary>
    /// Converts Windows path to WSL path format (/mnt/c/...) if needed
    /// </summary>
    public string ConvertPathIfNeeded(string windowsPath)
    {
        if (Mode != WiresharkExecutionMode.Wsl)
            return windowsPath;

        // Convert C:\path\to\file to /mnt/c/path/to/file
        if (windowsPath.Length >= 2 && windowsPath[1] == ':')
        {
            var driveLetter = char.ToLower(windowsPath[0]);
            var relativePath = windowsPath.Substring(2).Replace('\\', '/');
            return $"/mnt/{driveLetter}{relativePath}";
        }

        return windowsPath;
    }

    private static string QuoteIfNeeded(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "\"\"";

        return value.Contains(' ', StringComparison.Ordinal) ? $"\"{value}\"" : value;
    }
}

/// <summary>
/// Detects Wireshark tools (tshark, editcap) across Windows, WSL2, and Linux environments.
/// Handles platform-specific path resolution and WSL wrapper configuration.
/// </summary>
public static class WiresharkToolDetector
{
    /// <summary>
    /// Detects tshark availability and execution mode
    /// </summary>
    public static WiresharkToolInfo DetectTShark()
    {
        return DetectTool("tshark", "tshark.exe");
    }

    /// <summary>
    /// Detects editcap availability and execution mode
    /// </summary>
    public static WiresharkToolInfo DetectEditcap()
    {
        return DetectTool("editcap", "editcap.exe");
    }

    /// <summary>
    /// Detects capinfos availability and execution mode.
    /// capinfos provides fast packet count from pcap headers (milliseconds vs seconds).
    /// </summary>
    public static WiresharkToolInfo DetectCapinfos()
    {
        return DetectTool("capinfos", "capinfos.exe");
    }

    /// <summary>
    /// Generic tool detection logic
    /// </summary>
    private static WiresharkToolInfo DetectTool(string toolName, string windowsExeName)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // STEP 1: Try native Windows installation
            var nativePath = FindNativeWindowsTool(windowsExeName, toolName);
            if (!string.IsNullOrWhiteSpace(nativePath))
            {
                return new WiresharkToolInfo
                {
                    IsAvailable = true,
                    Mode = WiresharkExecutionMode.NativeWindows,
                    ExecutablePath = nativePath,
                    Description = $"Native Windows {toolName}"
                };
            }

            // STEP 2: Try WSL wrapper
            if (IsWslAvailable() && IsToolAvailableInWsl(toolName))
            {
                return new WiresharkToolInfo
                {
                    IsAvailable = true,
                    Mode = WiresharkExecutionMode.Wsl,
                    ExecutablePath = toolName,
                    Description = $"WSL {toolName}"
                };
            }

            // STEP 3: Not available
            return new WiresharkToolInfo
            {
                IsAvailable = false,
                Mode = WiresharkExecutionMode.Unavailable,
                ExecutablePath = string.Empty,
                Description = $"{toolName} not found. Install Wireshark or configure WSL with Wireshark tools."
            };
        }

        // Linux/Mac: Direct execution
        return new WiresharkToolInfo
        {
            IsAvailable = true,
            Mode = WiresharkExecutionMode.DirectUnix,
            ExecutablePath = toolName,
            Description = $"Direct {toolName}"
        };
    }

    /// <summary>
    /// Finds native Windows tool in standard Wireshark installation paths
    /// </summary>
    private static string? FindNativeWindowsTool(string exeName, string toolName)
    {
        // Check environment variable override
        var envVar = $"{toolName.ToUpperInvariant()}_PATH";
        var explicitPath = Environment.GetEnvironmentVariable(envVar);
        if (!string.IsNullOrWhiteSpace(explicitPath) && File.Exists(explicitPath))
            return explicitPath;

        // Standard Wireshark installation paths
        var candidates = new[]
        {
            $@"C:\Program Files\Wireshark\{exeName}",
            $@"C:\Program Files (x86)\Wireshark\{exeName}",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Wireshark", exeName),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Wireshark", exeName)
        };

        foreach (var candidate in candidates)
        {
            try
            {
                if (File.Exists(candidate))
                    return candidate;
            }
            catch
            {
                // Ignore access exceptions
            }
        }

        // Check PATH environment variable
        var pathEnv = Environment.GetEnvironmentVariable("PATH");
        if (!string.IsNullOrWhiteSpace(pathEnv))
        {
            foreach (var segment in pathEnv.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            {
                try
                {
                    var candidate = Path.Combine(segment.Trim(), exeName);
                    if (File.Exists(candidate))
                        return candidate;
                }
                catch
                {
                    // Ignore invalid paths
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Checks if WSL is available on Windows
    /// </summary>
    private static bool IsWslAvailable()
    {
        try
        {
            var systemDir = Environment.GetFolderPath(Environment.SpecialFolder.System);
            if (!string.IsNullOrWhiteSpace(systemDir))
            {
                var wslPath = Path.Combine(systemDir, "wsl.exe");
                if (File.Exists(wslPath))
                    return true;
            }
        }
        catch
        {
            // Ignore access exceptions
        }

        return false;
    }

    /// <summary>
    /// Checks if a tool is available in WSL environment
    /// </summary>
    private static bool IsToolAvailableInWsl(string toolName)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "wsl.exe",
                Arguments = $"which {toolName}",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process is null)
                return false;

            process.WaitForExit(2000);

            // Exit code 0 means tool found
            return process.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Tests if a tool works by running it with --version or -h
    /// </summary>
    public static bool TestTool(WiresharkToolInfo toolInfo, out string? version)
    {
        version = null;

        if (!toolInfo.IsAvailable)
            return false;

        try
        {
            var psi = toolInfo.CreateProcessStartInfo("--version");
            using var process = Process.Start(psi);
            if (process is null)
                return false;

            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(2000);

            if (process.ExitCode == 0)
            {
                version = output.Split('\n')[0].Trim();
                return true;
            }

            // Try -h for tools that don't support --version
            psi = toolInfo.CreateProcessStartInfo("-h");
            using var process2 = Process.Start(psi);
            if (process2 is null)
                return false;

            process2.WaitForExit(2000);

            // editcap returns exit code 1 with -h (displays help)
            if (process2.ExitCode == 0 || process2.ExitCode == 1)
            {
                version = "available";
                return true;
            }

            return false;
        }
        catch
        {
            return false;
        }
    }
}
