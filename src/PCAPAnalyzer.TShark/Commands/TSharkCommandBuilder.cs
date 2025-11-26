using System;
using System.Collections.Generic;
using System.Text;

namespace PCAPAnalyzer.TShark.Commands;

/// <summary>
/// Builder pattern for constructing optimized TShark command-line arguments.
/// Provides type-safe, fluent API for building efficient TShark commands.
/// </summary>
public sealed class TSharkCommandBuilder
{
    private readonly StringBuilder _arguments = new();
    private string? _inputFile;
    private OutputFormat _outputFormat = OutputFormat.Fields;
    private readonly List<string> _fields = new();
    private readonly List<string> _displayFilters = new();
    private readonly List<string> _readFilters = new();
    private string? _captureFilter;
    private bool _quietMode;
    private int? _packetCount;
    private string? _fieldSeparator;
    private FieldOccurrence _fieldOccurrence = FieldOccurrence.All;
    private bool _includeColumnHeaders;
    private bool _aggregateQuotes;
    private int? _snapshotLength;
    private bool _disableProtocolDissection;

    /// <summary>
    /// Sets the input PCAP/PCAPNG file to read
    /// </summary>
    public TSharkCommandBuilder WithInputFile(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentException("File path cannot be null or empty", nameof(filePath));

        _inputFile = filePath;
        return this;
    }

    /// <summary>
    /// Sets the output format (fields, json, ek, etc.)
    /// </summary>
    public TSharkCommandBuilder WithOutputFormat(OutputFormat format)
    {
        _outputFormat = format;
        return this;
    }

    /// <summary>
    /// Adds a field to extract. Only valid for Fields output format.
    /// </summary>
    public TSharkCommandBuilder AddField(string fieldName)
    {
        if (string.IsNullOrWhiteSpace(fieldName))
            throw new ArgumentException("Field name cannot be null or empty", nameof(fieldName));

        _fields.Add(fieldName);
        return this;
    }

    /// <summary>
    /// Adds multiple fields to extract
    /// </summary>
    public TSharkCommandBuilder AddFields(params string[] fields)
    {
        foreach (var field in fields)
        {
            AddField(field);
        }
        return this;
    }

    /// <summary>
    /// Adds a standard packet analysis field set optimized for performance
    /// </summary>
    public TSharkCommandBuilder WithStandardPacketFields()
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
    /// Adds a display filter (applied after packet parsing - slower but more flexible)
    /// </summary>
    public TSharkCommandBuilder WithDisplayFilter(string filter)
    {
        if (!string.IsNullOrWhiteSpace(filter))
        {
            _displayFilters.Add(filter);
        }
        return this;
    }

    /// <summary>
    /// Adds a read filter (applied during reading - faster, limited syntax)
    /// </summary>
    public TSharkCommandBuilder WithReadFilter(string filter)
    {
        if (!string.IsNullOrWhiteSpace(filter))
        {
            _readFilters.Add(filter);
        }
        return this;
    }

    /// <summary>
    /// Sets a capture filter (BPF syntax - fastest, but only for live capture or initial filtering)
    /// </summary>
    public TSharkCommandBuilder WithCaptureFilter(string filter)
    {
        if (!string.IsNullOrWhiteSpace(filter))
        {
            _captureFilter = filter;
        }
        return this;
    }

    /// <summary>
    /// Enables quiet mode (suppresses packet count messages)
    /// </summary>
    public TSharkCommandBuilder WithQuietMode(bool quiet = true)
    {
        _quietMode = quiet;
        return this;
    }

    /// <summary>
    /// Limits the number of packets to read
    /// </summary>
    public TSharkCommandBuilder WithPacketCount(int count)
    {
        if (count <= 0)
            throw new ArgumentException("Packet count must be positive", nameof(count));

        _packetCount = count;
        return this;
    }

    /// <summary>
    /// Sets the field separator for fields output format
    /// </summary>
    public TSharkCommandBuilder WithFieldSeparator(string separator)
    {
        _fieldSeparator = separator;
        return this;
    }

    /// <summary>
    /// Sets field occurrence mode (first, last, all)
    /// </summary>
    public TSharkCommandBuilder WithFieldOccurrence(FieldOccurrence occurrence)
    {
        _fieldOccurrence = occurrence;
        return this;
    }

    /// <summary>
    /// Includes column headers in output
    /// </summary>
    public TSharkCommandBuilder WithColumnHeaders(bool include = true)
    {
        _includeColumnHeaders = include;
        return this;
    }

    /// <summary>
    /// Aggregates field values with quotes
    /// </summary>
    public TSharkCommandBuilder WithAggregateQuotes(bool aggregate = true)
    {
        _aggregateQuotes = aggregate;
        return this;
    }

    /// <summary>
    /// Sets snapshot length (limits packet capture size)
    /// </summary>
    public TSharkCommandBuilder WithSnapshotLength(int length)
    {
        if (length <= 0)
            throw new ArgumentException("Snapshot length must be positive", nameof(length));

        _snapshotLength = length;
        return this;
    }

    /// <summary>
    /// Disables protocol dissection for faster parsing (use with fields only)
    /// </summary>
    public TSharkCommandBuilder WithDisableProtocolDissection(bool disable = true)
    {
        _disableProtocolDissection = disable;
        return this;
    }

    /// <summary>
    /// Creates a command builder optimized for packet counting
    /// </summary>
    public static TSharkCommandBuilder ForPacketCount(string pcapPath)
    {
        return new TSharkCommandBuilder()
            .WithInputFile(pcapPath)
            .WithOutputFormat(OutputFormat.Fields)
            .AddField("frame.number")
            .WithFieldOccurrence(FieldOccurrence.First)
            .WithQuietMode();
    }

    /// <summary>
    /// Creates a command builder optimized for streaming packet analysis
    /// </summary>
    public static TSharkCommandBuilder ForStreamingAnalysis(string pcapPath)
    {
        return new TSharkCommandBuilder()
            .WithInputFile(pcapPath)
            .WithOutputFormat(OutputFormat.Fields)
            .WithStandardPacketFields()
            .WithFieldOccurrence(FieldOccurrence.First)
            .WithQuietMode();
    }

    /// <summary>
    /// Creates a command builder optimized for protocol statistics
    /// </summary>
    public static TSharkCommandBuilder ForProtocolStats(string pcapPath)
    {
        return new TSharkCommandBuilder()
            .WithInputFile(pcapPath)
            .WithOutputFormat(OutputFormat.Fields)
            .AddFields("frame.number", "_ws.col.Protocol", "frame.len")
            .WithFieldOccurrence(FieldOccurrence.First)
            .WithQuietMode();
    }

    /// <summary>
    /// Builds the command-line arguments string
    /// </summary>
    public string Build()
    {
        if (string.IsNullOrWhiteSpace(_inputFile))
            throw new InvalidOperationException("Input file must be specified");

        _arguments.Clear();

        // Input file
        _arguments.Append($"-r \"{_inputFile}\"");

        // Quiet mode
        if (_quietMode)
        {
            _arguments.Append(" -q");
        }

        // Packet count limit
        if (_packetCount.HasValue)
        {
            _arguments.Append($" -c {_packetCount.Value}");
        }

        // Snapshot length
        if (_snapshotLength.HasValue)
        {
            _arguments.Append($" -s {_snapshotLength.Value}");
        }

        // Capture filter (BPF)
        if (!string.IsNullOrWhiteSpace(_captureFilter))
        {
            _arguments.Append($" -f \"{EscapeArgument(_captureFilter)}\"");
        }

        // Read filters (faster than display filters)
        if (_readFilters.Count > 0)
        {
            var combinedFilter = string.Join(" && ", _readFilters);
            _arguments.Append($" -Y \"{EscapeArgument(combinedFilter)}\"");
        }

        // Display filters (applied after read filters)
        if (_displayFilters.Count > 0)
        {
            var combinedFilter = string.Join(" && ", _displayFilters);
            _arguments.Append($" -Y \"{EscapeArgument(combinedFilter)}\"");
        }

        // Disable protocol dissection for performance
        if (_disableProtocolDissection)
        {
            _arguments.Append(" -d tcp.port==0-65535,data");
        }

        // Output format
        _arguments.Append($" -T {_outputFormat.ToString().ToLowerInvariant()}");

        // Fields (only for Fields format)
        if (_outputFormat == OutputFormat.Fields && _fields.Count > 0)
        {
            foreach (var field in _fields)
            {
                _arguments.Append($" -e {field}");
            }

            // Field occurrence
            _arguments.Append($" -E occurrence={_fieldOccurrence.ToString().ToLowerInvariant()[0]}");

            // Field separator
            if (!string.IsNullOrWhiteSpace(_fieldSeparator))
            {
                _arguments.Append($" -E separator={_fieldSeparator}");
            }

            // Column headers
            if (_includeColumnHeaders)
            {
                _arguments.Append(" -E header=y");
            }

            // Aggregate quotes
            if (_aggregateQuotes)
            {
                _arguments.Append(" -E quote=d");
            }
        }

        return _arguments.ToString();
    }

    /// <summary>
    /// Escapes special characters in command-line arguments
    /// </summary>
    private static string EscapeArgument(string arg)
    {
        if (string.IsNullOrEmpty(arg))
            return arg;

        // Escape backslashes and quotes
        return arg.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal);
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

        if (_displayFilters.Count > 0 && _readFilters.Count > 0)
        {
            // Both can be used, but warn that it might be redundant
            // This is not an error, just informational
        }

        return true;
    }
}

/// <summary>
/// TShark output formats
/// </summary>
public enum OutputFormat
{
    /// <summary>
    /// Tab-separated fields (fastest)
    /// </summary>
    Fields,

    /// <summary>
    /// JSON format (slower but structured)
    /// </summary>
    Json,

    /// <summary>
    /// JSON bulk format (for Elasticsearch)
    /// </summary>
    Ek,

    /// <summary>
    /// PDML (XML format - very slow)
    /// </summary>
    Pdml,

    /// <summary>
    /// PSML (summary XML)
    /// </summary>
    Psml,

    /// <summary>
    /// Text format (human-readable, slow)
    /// </summary>
    Text
}

/// <summary>
/// Field occurrence modes
/// </summary>
public enum FieldOccurrence
{
    /// <summary>
    /// First occurrence of field
    /// </summary>
    First,

    /// <summary>
    /// Last occurrence of field
    /// </summary>
    Last,

    /// <summary>
    /// All occurrences of field
    /// </summary>
    All
}
