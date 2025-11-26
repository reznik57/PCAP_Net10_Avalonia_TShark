using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.Reporting
{
    /// <summary>
    /// Interface for HTML report generation.
    /// Generates styled HTML reports with charts and interactive elements.
    /// </summary>
    public interface IHtmlReportGenerator
    {
        /// <summary>
        /// Generates an HTML report from the network analysis report.
        /// </summary>
        /// <param name="report">The network analysis report containing findings and statistics.</param>
        /// <returns>HTML content as a string.</returns>
        Task<string> GenerateAsync(NetworkAnalysisReport report);
    }
}
