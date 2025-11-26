using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.Reporting
{
    /// <summary>
    /// Interface for PDF report generation.
    /// Generates professional PDF reports using QuestPDF library.
    /// </summary>
    public interface IPdfReportGenerator
    {
        /// <summary>
        /// Generates a PDF report from the network analysis report.
        /// </summary>
        /// <param name="report">The network analysis report containing findings and statistics.</param>
        /// <returns>PDF content as a byte array.</returns>
        Task<byte[]> GenerateAsync(NetworkAnalysisReport report);
    }
}
