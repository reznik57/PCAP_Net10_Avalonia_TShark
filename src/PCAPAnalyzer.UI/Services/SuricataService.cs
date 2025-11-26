using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace PCAPAnalyzer.UI.Services;

public sealed class SuricataAlert
{
    public DateTime Timestamp { get; set; }
    public string SourceIP { get; set; } = string.Empty;
    public string DestinationIP { get; set; } = string.Empty;
    public string? AlertSignature { get; set; }
    public string? AlertCategory { get; set; }
    public int Severity { get; set; }
    public string RawJson { get; set; } = string.Empty;
}

public sealed class SuricataService
{
    private readonly string _scriptPath;
    private readonly string _ruleFile;

    public SuricataService(string scriptPath, string ruleFile)
    {
        _scriptPath = scriptPath;
        _ruleFile = ruleFile;
    }

    public bool IsAvailable => File.Exists(_scriptPath) && File.Exists(_ruleFile);

    public async Task<List<SuricataAlert>> RunAsync(string pcapPath, string outputDir, CancellationToken cancellationToken)
    {
        if (!IsAvailable)
            return new List<SuricataAlert>();

        Directory.CreateDirectory(outputDir);
        var evePath = Path.Combine(outputDir, "eve.json");

        var psi = new ProcessStartInfo
        {
            FileName = _scriptPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        psi.ArgumentList.Add(pcapPath);
        psi.ArgumentList.Add(outputDir);
        psi.ArgumentList.Add(_ruleFile);

        using var process = Process.Start(psi);
        if (process == null)
            throw new InvalidOperationException("Failed to launch Suricata helper script");

        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

        if (!File.Exists(evePath))
            return new List<SuricataAlert>();

        var alerts = new List<SuricataAlert>();
        using var stream = File.OpenRead(evePath);
        using var reader = new StreamReader(stream);
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            if (string.IsNullOrWhiteSpace(line))
                continue;

            try
            {
                using var doc = JsonDocument.Parse(line);
                if (!doc.RootElement.TryGetProperty("event_type", out var eventType) || eventType.GetString() != "alert")
                    continue;

                var alert = new SuricataAlert
                {
                    Timestamp = doc.RootElement.TryGetProperty("timestamp", out var ts) && DateTime.TryParse(ts.GetString(), out var dt) ? dt : DateTime.MinValue,
                    SourceIP = doc.RootElement.TryGetProperty("src_ip", out var src) ? src.GetString() ?? string.Empty : string.Empty,
                    DestinationIP = doc.RootElement.TryGetProperty("dest_ip", out var dst) ? dst.GetString() ?? string.Empty : string.Empty,
                    RawJson = line
                };

                if (doc.RootElement.TryGetProperty("alert", out var alertObj))
                {
                    alert.AlertSignature = alertObj.TryGetProperty("signature", out var sig) ? sig.GetString() : null;
                    alert.AlertCategory = alertObj.TryGetProperty("category", out var cat) ? cat.GetString() : null;
                    alert.Severity = alertObj.TryGetProperty("severity", out var sevElem) && int.TryParse(sevElem.GetRawText(), out var sev) ? sev : 0;
                }

                alerts.Add(alert);
            }
            catch
            {
                // Ignore parsing issues; continue with other lines.
            }
        }

        return alerts;
    }
}
