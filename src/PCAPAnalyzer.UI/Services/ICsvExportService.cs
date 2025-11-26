using System.Collections.Generic;
using System.Threading.Tasks;

namespace PCAPAnalyzer.UI.Services;

/// <summary>
/// Interface for CSV export service
/// </summary>
public interface ICsvExportService
{
    /// <summary>
    /// Export data to CSV file with custom column mappings
    /// </summary>
    Task ExportToCsvAsync<T>(
        IEnumerable<T> data,
        string filePath,
        Dictionary<string, System.Func<T, object?>> columnMappings,
        bool includeHeaders = true);

    /// <summary>
    /// Export protocol distribution data to CSV
    /// </summary>
    Task ExportProtocolDistributionAsync(IEnumerable<dynamic> data, string filePath);

    /// <summary>
    /// Export top talkers data to CSV
    /// </summary>
    Task ExportTopTalkersAsync(IEnumerable<dynamic> data, string filePath);

    /// <summary>
    /// Export port analysis data to CSV
    /// </summary>
    Task ExportPortAnalysisAsync(IEnumerable<dynamic> data, string filePath);

    /// <summary>
    /// Export country traffic data to CSV
    /// </summary>
    Task ExportCountryTrafficAsync(IEnumerable<dynamic> data, string filePath);

    /// <summary>
    /// Export threat list to CSV
    /// </summary>
    Task ExportThreatsAsync(IEnumerable<dynamic> data, string filePath);

    /// <summary>
    /// Export anomaly list to CSV
    /// </summary>
    Task ExportAnomaliesAsync(IEnumerable<dynamic> data, string filePath);

    /// <summary>
    /// Export packet list to CSV
    /// </summary>
    Task ExportPacketsAsync(IEnumerable<dynamic> data, string filePath);

    /// <summary>
    /// Get suggested filename for export based on data type
    /// </summary>
    string GetSuggestedFileName(string dataType);

    /// <summary>
    /// Validate export path and create directory if needed
    /// </summary>
    Task<bool> ValidateAndPreparePathAsync(string filePath);

    /// <summary>
    /// Get CSV file filter for file dialogs
    /// </summary>
    string GetFileFilter();
}
