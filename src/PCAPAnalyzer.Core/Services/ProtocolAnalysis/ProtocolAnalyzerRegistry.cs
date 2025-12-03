using System;
using System.Collections.Generic;
using System.Linq;
using PCAPAnalyzer.Core.Services.ProtocolAnalysis.Analyzers;

namespace PCAPAnalyzer.Core.Services.ProtocolAnalysis;

/// <summary>
/// Central registry for protocol analyzers.
/// Dispatches protocol layers to appropriate analyzers based on protocol type.
/// </summary>
public class ProtocolAnalyzerRegistry
{
    private readonly List<IProtocolAnalyzer> _analyzers;

    public ProtocolAnalyzerRegistry()
    {
        // Register all protocol analyzers
        _analyzers = new List<IProtocolAnalyzer>
        {
            new HttpAnalyzer(),
            new FtpAnalyzer(),
            new TelnetAnalyzer(),
            new SmtpAnalyzer(),
            new Pop3Analyzer(),
            new ImapAnalyzer(),
            new LdapAnalyzer(),
            new MysqlAnalyzer(),
            new PostgresAnalyzer(),
            new RedisAnalyzer(),
            new SnmpAnalyzer(),
            new SipAnalyzer(),
            new RtspAnalyzer(),
            new DnsAnalyzer()
        };
    }

    /// <summary>
    /// Extracts cleartext content from a protocol layer using registered analyzers.
    /// Returns null if no analyzer can handle the layer.
    /// </summary>
    public CleartextContent? AnalyzeLayer(ProtocolLayer layer)
    {
        var layerName = layer.Name.ToUpperInvariant();

        // Find first matching analyzer
        var analyzer = _analyzers.FirstOrDefault(a => a.CanAnalyze(layerName));
        if (analyzer == null)
            return null;

        return analyzer.Analyze(layer);
    }

    /// <summary>
    /// Gets all registered protocol names.
    /// </summary>
    public IReadOnlyList<string> GetSupportedProtocols()
    {
        return _analyzers.Select(a => a.Protocol).ToList();
    }

    /// <summary>
    /// Gets analyzer count for diagnostics.
    /// </summary>
    public int AnalyzerCount => _analyzers.Count;
}
