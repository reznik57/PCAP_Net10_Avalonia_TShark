using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.Reporting
{
    /// <summary>
    /// Interface for JSON report generation.
    /// Serializes network analysis reports to structured JSON format.
    /// </summary>
    public interface IJsonReportGenerator
    {
        /// <summary>
        /// Generates a JSON representation of the network analysis report.
        /// </summary>
        /// <param name="report">The network analysis report containing findings and statistics.</param>
        /// <returns>JSON content as a string.</returns>
        Task<string> GenerateAsync(NetworkAnalysisReport report);
    }
}
