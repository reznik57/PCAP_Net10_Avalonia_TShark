namespace PCAPAnalyzer.Core.Services.ProtocolAnalysis;

/// <summary>
/// Interface for protocol-specific cleartext content analyzers.
/// Each analyzer handles extraction of credentials and sensitive data for a specific protocol.
/// </summary>
public interface IProtocolAnalyzer
{
    /// <summary>
    /// Protocol name (e.g., "HTTP", "FTP", "DNS").
    /// </summary>
    string Protocol { get; }

    /// <summary>
    /// Keywords that identify this protocol in layer names.
    /// </summary>
    string[] Keywords { get; }

    /// <summary>
    /// Determines if this analyzer can handle the given protocol layer.
    /// </summary>
    bool CanAnalyze(string layerName);

    /// <summary>
    /// Analyzes a protocol layer and extracts cleartext content.
    /// Returns null if no relevant content found.
    /// </summary>
    CleartextContent? Analyze(ProtocolLayer layer);
}
