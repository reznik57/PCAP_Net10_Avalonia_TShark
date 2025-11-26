using PCAPAnalyzer.API.DTOs;

namespace PCAPAnalyzer.API.Services;

/// <summary>
/// PCAP analysis service interface
/// </summary>
public interface IPcapAnalysisService
{
    Task<PcapUploadResponse> UploadPcapAsync(PcapUploadRequest request, CancellationToken cancellationToken = default);
    Task<AnalysisStatusResponse> StartAnalysisAsync(string pcapId, AnalyzeRequest request, CancellationToken cancellationToken = default);
    Task<AnalysisStatusResponse> GetAnalysisStatusAsync(string pcapId, CancellationToken cancellationToken = default);
    Task<object> GetAnalysisResultsAsync(string pcapId, CancellationToken cancellationToken = default);
    Task<bool> DeletePcapAsync(string pcapId, CancellationToken cancellationToken = default);
}

/// <summary>
/// Statistics service interface
/// </summary>
public interface IStatisticsService
{
    Task<StatisticsSummaryDto> GetSummaryAsync(string pcapId, CancellationToken cancellationToken = default);
    Task<IEnumerable<ProtocolStatisticsDto>> GetProtocolsAsync(string pcapId, CancellationToken cancellationToken = default);
    Task<PaginatedResult<ConversationDto>> GetConversationsAsync(string pcapId, int page, int pageSize, CancellationToken cancellationToken = default);
    Task<IEnumerable<GeographicStatisticsDto>> GetGeographicAsync(string pcapId, CancellationToken cancellationToken = default);
}

/// <summary>
/// Anomaly detection service interface
/// </summary>
public interface IAnomalyDetectionService
{
    Task<IEnumerable<AnomalyDto>> GetAnomaliesAsync(string pcapId, CancellationToken cancellationToken = default);
    Task<ModelInfoDto> TrainModelAsync(TrainModelRequest request, CancellationToken cancellationToken = default);
    Task<IEnumerable<ModelInfoDto>> GetAvailableModelsAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Capture service interface
/// </summary>
public interface ICaptureService
{
    Task<IEnumerable<NetworkInterfaceDto>> GetInterfacesAsync(CancellationToken cancellationToken = default);
    Task<CaptureSessionDto> StartCaptureAsync(StartCaptureRequest request, CancellationToken cancellationToken = default);
    Task<CaptureSessionDto> StopCaptureAsync(string sessionId, CancellationToken cancellationToken = default);
    Task<CaptureSessionDto> GetCaptureStatusAsync(string sessionId, CancellationToken cancellationToken = default);
}

/// <summary>
/// Export service interface
/// </summary>
public interface IExportService
{
    Task<ExportResponse> ExportToPdfAsync(string pcapId, ExportRequest request, CancellationToken cancellationToken = default);
    Task<ExportResponse> ExportToCsvAsync(string pcapId, ExportRequest request, CancellationToken cancellationToken = default);
    Task<ExportResponse> ExportToJsonAsync(string pcapId, ExportRequest request, CancellationToken cancellationToken = default);
    Task<Stream> DownloadExportAsync(string exportId, CancellationToken cancellationToken = default);
}
