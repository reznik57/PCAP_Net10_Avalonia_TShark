using PCAPAnalyzer.API.DTOs;
using System.Collections.Concurrent;

namespace PCAPAnalyzer.API.Services;

public class PcapAnalysisService : IPcapAnalysisService
{
    private readonly ILogger<PcapAnalysisService> _logger;
    private readonly ConcurrentDictionary<string, PcapFileInfo> _pcapFiles = [];
    private readonly ConcurrentDictionary<string, AnalysisJob> _analysisJobs = [];

    public PcapAnalysisService(ILogger<PcapAnalysisService> logger)
    {
        _logger = logger;
    }

    public async Task<PcapUploadResponse> UploadPcapAsync(PcapUploadRequest request, CancellationToken cancellationToken = default)
    {
        var pcapId = Guid.NewGuid().ToString("N");
        var uploadPath = Path.Combine(Path.GetTempPath(), "pcap-uploads", pcapId);
        Directory.CreateDirectory(uploadPath);

        var filePath = Path.Combine(uploadPath, request.FileName!);
        await File.WriteAllBytesAsync(filePath, request.FileData!, cancellationToken);

        var fileInfo = new PcapFileInfo
        {
            Id = pcapId,
            FileName = request.FileName!,
            FilePath = filePath,
            FileSize = request.FileSize,
            UploadedAt = DateTime.UtcNow,
            Metadata = request.Metadata
        };

        _pcapFiles[pcapId] = fileInfo;

        _logger.LogInformation("PCAP file uploaded: {PcapId}, {FileName}", pcapId, request.FileName);

        return new PcapUploadResponse
        {
            PcapId = pcapId,
            FileName = request.FileName!,
            FileSize = request.FileSize,
            UploadedAt = fileInfo.UploadedAt,
            Status = "uploaded",
            Links = new Dictionary<string, string>
            {
                { "analyze", $"/api/v1/pcap/{pcapId}/analyze" },
                { "status", $"/api/v1/pcap/{pcapId}/status" },
                { "delete", $"/api/v1/pcap/{pcapId}" }
            }
        };
    }

    public Task<AnalysisStatusResponse> StartAnalysisAsync(string pcapId, AnalyzeRequest request, CancellationToken cancellationToken = default)
    {
        if (!_pcapFiles.ContainsKey(pcapId))
            throw new FileNotFoundException($"PCAP file not found: {pcapId}");

        var jobId = Guid.NewGuid().ToString("N");
        var job = new AnalysisJob
        {
            Id = jobId,
            PcapId = pcapId,
            Status = "running",
            StartedAt = DateTime.UtcNow,
            ProgressPercent = 0,
            CurrentStep = "Initializing analysis"
        };

        _analysisJobs[pcapId] = job;

        // Start background analysis (fire-and-forget pattern)
        _ = Task.Run(async () => await PerformAnalysisAsync(pcapId, request, cancellationToken), cancellationToken);

        _logger.LogInformation("Analysis started for PCAP: {PcapId}", pcapId);

        return Task.FromResult(MapToStatusResponse(job));
    }

    public Task<AnalysisStatusResponse> GetAnalysisStatusAsync(string pcapId, CancellationToken cancellationToken = default)
    {
        if (!_analysisJobs.TryGetValue(pcapId, out var job))
            throw new FileNotFoundException($"Analysis not found for PCAP: {pcapId}");

        return Task.FromResult(MapToStatusResponse(job));
    }

    public Task<object> GetAnalysisResultsAsync(string pcapId, CancellationToken cancellationToken = default)
    {
        if (!_analysisJobs.TryGetValue(pcapId, out var job))
            throw new FileNotFoundException($"Analysis not found for PCAP: {pcapId}");

        if (job.Status != "completed")
            throw new InvalidOperationException($"Analysis is not completed. Current status: {job.Status}");

        // Return mock results for now
        var results = new
        {
            pcapId,
            summary = new
            {
                totalPackets = 15234,
                totalBytes = 12456789L,
                duration = TimeSpan.FromMinutes(5.5),
                protocols = new[] { "TCP", "UDP", "ICMP", "ARP" }
            },
            completedAt = job.CompletedAt
        };

        return Task.FromResult<object>(results);
    }

    public Task<bool> DeletePcapAsync(string pcapId, CancellationToken cancellationToken = default)
    {
        if (_pcapFiles.TryRemove(pcapId, out var fileInfo))
        {
            try
            {
                if (File.Exists(fileInfo.FilePath))
                    File.Delete(fileInfo.FilePath);

                var directory = Path.GetDirectoryName(fileInfo.FilePath);
                if (directory is not null && Directory.Exists(directory))
                    Directory.Delete(directory, true);

                _analysisJobs.TryRemove(pcapId, out _);

                _logger.LogInformation("PCAP file deleted: {PcapId}", pcapId);
                return Task.FromResult(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting PCAP file: {PcapId}", pcapId);
                return Task.FromResult(false);
            }
        }

        return Task.FromResult(false);
    }

    private async Task PerformAnalysisAsync(string pcapId, AnalyzeRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var job = _analysisJobs[pcapId];

            // Simulate analysis steps
            await Task.Delay(1000, cancellationToken);
            job.ProgressPercent = 25;
            job.CurrentStep = "Parsing packets";

            await Task.Delay(1000, cancellationToken);
            job.ProgressPercent = 50;
            job.CurrentStep = "Analyzing protocols";

            await Task.Delay(1000, cancellationToken);
            job.ProgressPercent = 75;
            job.CurrentStep = "Detecting anomalies";

            await Task.Delay(1000, cancellationToken);
            job.ProgressPercent = 100;
            job.CurrentStep = "Completed";
            job.Status = "completed";
            job.CompletedAt = DateTime.UtcNow;

            _logger.LogInformation("Analysis completed for PCAP: {PcapId}", pcapId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Analysis failed for PCAP: {PcapId}", pcapId);
            var job = _analysisJobs[pcapId];
            job.Status = "failed";
            job.ErrorMessage = ex.Message;
            job.CompletedAt = DateTime.UtcNow;
        }
    }

    private static AnalysisStatusResponse MapToStatusResponse(AnalysisJob job)
    {
        return new AnalysisStatusResponse
        {
            PcapId = job.PcapId,
            Status = job.Status,
            ProgressPercent = job.ProgressPercent,
            CurrentStep = job.CurrentStep,
            StartedAt = job.StartedAt,
            CompletedAt = job.CompletedAt,
            ErrorMessage = job.ErrorMessage,
            Links = new Dictionary<string, string>
            {
                { "status", $"/api/v1/pcap/{job.PcapId}/status" },
                { "results", $"/api/v1/pcap/{job.PcapId}/results" }
            }
        };
    }

    private class PcapFileInfo
    {
        public required string Id { get; set; }
        public required string FileName { get; set; }
        public required string FilePath { get; set; }
        public long FileSize { get; set; }
        public DateTime UploadedAt { get; set; }
        public Dictionary<string, string>? Metadata { get; set; }
    }

    private class AnalysisJob
    {
        public required string Id { get; set; }
        public required string PcapId { get; set; }
        public required string Status { get; set; }
        public int ProgressPercent { get; set; }
        public string? CurrentStep { get; set; }
        public DateTime? StartedAt { get; set; }
        public DateTime? CompletedAt { get; set; }
        public string? ErrorMessage { get; set; }
    }
}
