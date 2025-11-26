using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace PCAPAnalyzer.UI.Services;

public sealed class YaraMatch
{
    public string RuleName { get; set; } = string.Empty;
    public string Namespace { get; set; } = string.Empty;
    public string Target { get; set; } = string.Empty;
    public string RawLine { get; set; } = string.Empty;
}

public sealed class YaraService
{
    private readonly string _scriptPath;
    private readonly string _rulesDirectory;

    public YaraService(string scriptPath, string rulesDirectory)
    {
        _scriptPath = scriptPath;
        _rulesDirectory = rulesDirectory;
    }

    public bool IsAvailable => File.Exists(_scriptPath) && Directory.Exists(_rulesDirectory);

    public async Task<List<YaraMatch>> RunAsync(string pcapPath, string outputPath, CancellationToken cancellationToken)
    {
        if (!IsAvailable)
            return new List<YaraMatch>();

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);

        var psi = new ProcessStartInfo
        {
            FileName = _scriptPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        psi.ArgumentList.Add(_rulesDirectory);
        psi.ArgumentList.Add(pcapPath);
        psi.ArgumentList.Add(outputPath);

        using var process = Process.Start(psi);
        if (process == null)
            throw new InvalidOperationException("Failed to launch YARA helper script");

        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

        var matches = new List<YaraMatch>();
        if (!File.Exists(outputPath))
            return matches;

        foreach (var line in await File.ReadAllLinesAsync(outputPath, cancellationToken))
        {
            if (string.IsNullOrWhiteSpace(line))
                continue;

            // Expected format: <namespace> <rule> <target>
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 3)
            {
                matches.Add(new YaraMatch
                {
                    Namespace = parts[0],
                    RuleName = parts[1],
                    Target = string.Join(' ', parts, 2, parts.Length - 2),
                    RawLine = line
                });
            }
        }

        return matches;
    }
}
