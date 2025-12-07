using System;
using System.Text.Json;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.Reporting
{
    /// <summary>
    /// Generates JSON formatted network analysis reports for programmatic consumption.
    /// Implements JSON serialization with proper formatting for integration with SIEM systems and automation tools.
    /// </summary>
    public class JsonReportGenerator : IJsonReportGenerator
    {
        private readonly JsonSerializerOptions _serializerOptions;

        /// <summary>
        /// Initializes a new instance of the JsonReportGenerator with configured serialization options.
        /// </summary>
        public JsonReportGenerator()
        {
            _serializerOptions = new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            };
        }

        /// <summary>
        /// Generates a JSON formatted report from the network analysis data.
        /// </summary>
        /// <param name="report">Network analysis report containing all findings and metrics</param>
        /// <returns>JSON document as string with proper indentation</returns>
        /// <exception cref="ArgumentNullException">Thrown when report is null</exception>
        /// <exception cref="JsonException">Thrown when serialization fails</exception>
        public async Task<string> GenerateAsync(NetworkAnalysisReport report)
        {
            ArgumentNullException.ThrowIfNull(report);

            try
            {
                var json = JsonSerializer.Serialize(report, _serializerOptions);
                return await Task.FromResult(json);
            }
            catch (Exception ex)
            {
                throw new JsonException($"Failed to serialize report to JSON: {ex.Message}", ex);
            }
        }
    }
}
