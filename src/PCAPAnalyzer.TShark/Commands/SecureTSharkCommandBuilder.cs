using System;
using System.Collections.Generic;
using System.Diagnostics;
using PCAPAnalyzer.TShark.Security;

namespace PCAPAnalyzer.TShark.Commands;

/// <summary>
/// Secure builder pattern for constructing TShark command execution using ProcessStartInfo.ArgumentList.
/// Provides type-safe, fluent API for building secure TShark commands that prevent command injection.
/// </summary>
/// <remarks>
/// SECURITY: This builder uses ProcessStartInfo.ArgumentList instead of string-based Arguments
/// to prevent shell command injection vulnerabilities. All inputs are validated before being added.
/// </remarks>
public sealed class SecureTSharkCommandBuilder
{
    private readonly TSharkInputValidator _validator;
    private string? _inputFile;
    private OutputFormat _outputFormat = OutputFormat.Fields;
    private readonly List<string> _fields = new();
    private string? _displayFilter;
    private bool _quietMode;
    private int? _packetCount;
    private FieldOccurrence _fieldOccurrence = FieldOccurrence.First;

    public SecureTSharkCommandBuilder(TSharkInputValidator validator)
    {
        _validator = validator ?? throw new ArgumentNullException(nameof(validator));
    }

    /// <summary>
    /// Sets the input PCAP/PCAPNG file to read (will be validated)
    /// </summary>
    public SecureTSharkCommandBuilder WithInputFile(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentException("File path cannot be null or empty", nameof(filePath));

        // Validate immediately
        _inputFile = _validator.ValidatePath(filePath);
        return this;
    }

    /// <summary>
    /// Sets the output format (fields, json, etc.)
    /// </summary>
    public SecureTSharkCommandBuilder WithOutputFormat(OutputFormat format)
    {
        _outputFormat = format;
        return this;
    }

    /// <summary>
    /// Adds a field to extract. Field name will be validated.
    /// </summary>
    public SecureTSharkCommandBuilder AddField(string fieldName)
    {
        if (string.IsNullOrWhiteSpace(fieldName))
            throw new ArgumentException("Field name cannot be null or empty", nameof(fieldName));

        // Validate immediately
        var validatedField = _validator.ValidateField(fieldName);
        _fields.Add(validatedField);
        return this;
    }

    /// <summary>
    /// Adds multiple fields to extract (all will be validated)
    /// </summary>
    public SecureTSharkCommandBuilder AddFields(params string[] fields)
    {
        var validatedFields = _validator.ValidateFields(fields);
        _fields.AddRange(validatedFields);
        return this;
    }

    /// <summary>
    /// Adds a standard packet analysis field set optimized for performance
    /// </summary>
    public SecureTSharkCommandBuilder WithStandardPacketFields()
    {
        return AddFields(
            "frame.number",
            "frame.time",
            "frame.time_epoch",
            "frame.len",
            "ip.src",
            "ip.dst",
            "ipv6.src",
            "ipv6.dst",
            "tcp.srcport",
            "tcp.dstport",
            "udp.srcport",
            "udp.dstport",
            "_ws.col.Protocol",
            "frame.protocols",
            "_ws.col.Info"
        );
    }

    /// <summary>
    /// Adds a Wireshark display filter (will be validated)
    /// </summary>
    public SecureTSharkCommandBuilder WithDisplayFilter(string filter)
    {
        if (!string.IsNullOrWhiteSpace(filter))
        {
            // Validate immediately
            _displayFilter = _validator.ValidateFilter(filter);
        }
        return this;
    }

    /// <summary>
    /// Enables quiet mode (suppresses packet count messages)
    /// </summary>
    public SecureTSharkCommandBuilder WithQuietMode(bool quiet = true)
    {
        _quietMode = quiet;
        return this;
    }

    /// <summary>
    /// Limits the number of packets to read
    /// </summary>
    public SecureTSharkCommandBuilder WithPacketCount(int count)
    {
        if (count <= 0)
            throw new ArgumentException("Packet count must be positive", nameof(count));

        _packetCount = count;
        return this;
    }

    /// <summary>
    /// Sets field occurrence mode (first, last, all)
    /// </summary>
    public SecureTSharkCommandBuilder WithFieldOccurrence(FieldOccurrence occurrence)
    {
        _fieldOccurrence = occurrence;
        return this;
    }

    /// <summary>
    /// Creates a command builder optimized for packet counting
    /// </summary>
    public static SecureTSharkCommandBuilder ForPacketCount(string pcapPath, TSharkInputValidator validator)
    {
        return new SecureTSharkCommandBuilder(validator)
            .WithInputFile(pcapPath)
            .WithOutputFormat(OutputFormat.Fields)
            .AddField("frame.number")
            .WithFieldOccurrence(FieldOccurrence.First)
            .WithQuietMode();
    }

    /// <summary>
    /// Creates a command builder optimized for streaming packet analysis
    /// </summary>
    public static SecureTSharkCommandBuilder ForStreamingAnalysis(string pcapPath, TSharkInputValidator validator)
    {
        return new SecureTSharkCommandBuilder(validator)
            .WithInputFile(pcapPath)
            .WithOutputFormat(OutputFormat.Fields)
            .WithStandardPacketFields()
            .WithFieldOccurrence(FieldOccurrence.First)
            .WithQuietMode();
    }

    /// <summary>
    /// Builds a secure ProcessStartInfo with ArgumentList (NO shell interpretation).
    /// </summary>
    /// <param name="tsharkExecutable">Path to the TShark executable</param>
    /// <returns>Configured ProcessStartInfo with ArgumentList</returns>
    /// <remarks>
    /// SECURITY: This method uses ArgumentList to prevent command injection.
    /// All arguments are added individually with no shell interpretation.
    /// </remarks>
    public ProcessStartInfo BuildProcessStartInfo(string tsharkExecutable)
    {
        if (string.IsNullOrWhiteSpace(_inputFile))
            throw new InvalidOperationException("Input file must be specified");

        if (_outputFormat == OutputFormat.Fields && _fields.Count == 0)
            throw new InvalidOperationException("At least one field must be specified for Fields output format");

        var startInfo = new ProcessStartInfo
        {
            FileName = tsharkExecutable,
            UseShellExecute = false, // CRITICAL: Must be false for ArgumentList
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = System.Text.Encoding.UTF8,
            StandardErrorEncoding = System.Text.Encoding.UTF8
        };

        // Build arguments using ArgumentList (SECURE - no shell interpretation)

        // Input file (-r)
        startInfo.ArgumentList.Add("-r");
        startInfo.ArgumentList.Add(_inputFile); // Already validated

        // Quiet mode (-q)
        if (_quietMode)
        {
            startInfo.ArgumentList.Add("-q");
        }

        // Packet count limit (-c)
        if (_packetCount.HasValue)
        {
            startInfo.ArgumentList.Add("-c");
            startInfo.ArgumentList.Add(_packetCount.Value.ToString());
        }

        // Display filter (-Y)
        if (!string.IsNullOrEmpty(_displayFilter))
        {
            startInfo.ArgumentList.Add("-Y");
            startInfo.ArgumentList.Add(_displayFilter); // Already validated
        }

        // Output format (-T)
        startInfo.ArgumentList.Add("-T");
        startInfo.ArgumentList.Add(_outputFormat.ToString().ToLowerInvariant());

        // Fields (only for Fields format)
        if (_outputFormat == OutputFormat.Fields)
        {
            foreach (var field in _fields)
            {
                startInfo.ArgumentList.Add("-e");
                startInfo.ArgumentList.Add(field); // Already validated
            }

            // Field occurrence (-E occurrence=)
            startInfo.ArgumentList.Add("-E");
            startInfo.ArgumentList.Add($"occurrence={_fieldOccurrence.ToString().ToLowerInvariant()[0]}");
        }

        return startInfo;
    }

    /// <summary>
    /// Builds a ProcessStartInfo for WSL execution.
    /// </summary>
    /// <param name="wslTsharkCommand">TShark command in WSL (typically just "tshark")</param>
    /// <param name="wslPath">The WSL-formatted path (already validated)</param>
    /// <returns>Configured ProcessStartInfo for WSL execution</returns>
    /// <remarks>
    /// SECURITY: For WSL execution, we launch wsl.exe and pass arguments individually.
    /// The WSL path must be validated before calling this method.
    /// </remarks>
    public ProcessStartInfo BuildWslProcessStartInfo(string wslTsharkCommand, string wslPath)
    {
        if (string.IsNullOrWhiteSpace(_inputFile))
            throw new InvalidOperationException("Input file must be specified");

        // Validate WSL path (defense in depth)
        _validator.ValidateWslPath(wslPath);

        var startInfo = new ProcessStartInfo
        {
            FileName = "wsl.exe",
            UseShellExecute = false, // CRITICAL
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = System.Text.Encoding.UTF8,
            StandardErrorEncoding = System.Text.Encoding.UTF8
        };

        // Add WSL tshark command
        startInfo.ArgumentList.Add(wslTsharkCommand);

        // Build arguments (same as native, but with WSL path)
        startInfo.ArgumentList.Add("-r");
        startInfo.ArgumentList.Add(wslPath); // Already validated

        if (_quietMode)
        {
            startInfo.ArgumentList.Add("-q");
        }

        if (_packetCount.HasValue)
        {
            startInfo.ArgumentList.Add("-c");
            startInfo.ArgumentList.Add(_packetCount.Value.ToString());
        }

        if (!string.IsNullOrEmpty(_displayFilter))
        {
            startInfo.ArgumentList.Add("-Y");
            startInfo.ArgumentList.Add(_displayFilter); // Already validated
        }

        startInfo.ArgumentList.Add("-T");
        startInfo.ArgumentList.Add(_outputFormat.ToString().ToLowerInvariant());

        if (_outputFormat == OutputFormat.Fields)
        {
            foreach (var field in _fields)
            {
                startInfo.ArgumentList.Add("-e");
                startInfo.ArgumentList.Add(field); // Already validated
            }

            startInfo.ArgumentList.Add("-E");
            startInfo.ArgumentList.Add($"occurrence={_fieldOccurrence.ToString().ToLowerInvariant()[0]}");
        }

        return startInfo;
    }

    /// <summary>
    /// Validates the command configuration before building
    /// </summary>
    public bool IsValid(out string? errorMessage)
    {
        errorMessage = null;

        if (string.IsNullOrWhiteSpace(_inputFile))
        {
            errorMessage = "Input file must be specified";
            return false;
        }

        if (_outputFormat == OutputFormat.Fields && _fields.Count == 0)
        {
            errorMessage = "At least one field must be specified for Fields output format";
            return false;
        }

        return true;
    }
}
