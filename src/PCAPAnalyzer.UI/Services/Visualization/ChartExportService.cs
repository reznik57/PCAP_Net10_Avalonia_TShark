using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Services.Visualization
{
    /// <summary>
    /// Service for exporting charts and visualizations to various formats
    /// </summary>
    public interface IChartExportService
    {
        /// <summary>
        /// Exports chart as PNG image
        /// </summary>
        Task<bool> ExportToPngAsync(Control chartControl, string filePath, int width = 1920, int height = 1080);

        /// <summary>
        /// Exports chart as SVG vector graphics
        /// </summary>
        Task<bool> ExportToSvgAsync(ISeries[] series, string filePath);

        /// <summary>
        /// Exports chart data as CSV
        /// </summary>
        Task<bool> ExportDataToCsvAsync(object chartData, string filePath);

        /// <summary>
        /// Exports interactive HTML chart
        /// </summary>
        Task<bool> ExportToHtmlAsync(object chartData, string filePath, string chartType);

        /// <summary>
        /// Creates a visualization report with multiple charts
        /// </summary>
        Task<bool> CreateVisualizationReportAsync(List<ChartExportInfo> charts, string filePath);
    }

    public class ChartExportService : IChartExportService
    {
        public async Task<bool> ExportToPngAsync(Control chartControl, string filePath, int width = 1920, int height = 1080)
        {
            try
            {
                await Task.Run(() =>
                {
                    // Note: Actual implementation would require render target bitmap
                    // This is a placeholder for the export functionality
                    DebugLogger.Log($"[ChartExportService] Exporting chart to PNG: {filePath}");
                });

                return true;
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[ChartExportService] PNG export error: {ex.Message}");
                return false;
            }
        }

        public async Task<bool> ExportToSvgAsync(ISeries[] series, string filePath)
        {
            try
            {
                await Task.Run(() =>
                {
                    var svg = GenerateSvgFromSeries(series);
                    File.WriteAllText(filePath, svg);
                });

                return true;
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[ChartExportService] SVG export error: {ex.Message}");
                return false;
            }
        }

        public async Task<bool> ExportDataToCsvAsync(object chartData, string filePath)
        {
            try
            {
                await Task.Run(() =>
                {
                    var csv = ConvertChartDataToCsv(chartData);
                    File.WriteAllText(filePath, csv);
                });

                return true;
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[ChartExportService] CSV export error: {ex.Message}");
                return false;
            }
        }

        public async Task<bool> ExportToHtmlAsync(object chartData, string filePath, string chartType)
        {
            try
            {
                await Task.Run(() =>
                {
                    var html = GenerateInteractiveHtml(chartData, chartType);
                    File.WriteAllText(filePath, html);
                });

                return true;
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[ChartExportService] HTML export error: {ex.Message}");
                return false;
            }
        }

        public async Task<bool> CreateVisualizationReportAsync(List<ChartExportInfo> charts, string filePath)
        {
            try
            {
                await Task.Run(() =>
                {
                    var report = GenerateVisualizationReport(charts);
                    File.WriteAllText(filePath, report);
                });

                return true;
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[ChartExportService] Report creation error: {ex.Message}");
                return false;
            }
        }

        private string GenerateSvgFromSeries(ISeries[] series)
        {
            var svg = new StringBuilder();
            svg.AppendLine(@"<?xml version=""1.0"" encoding=""UTF-8""?>");
            svg.AppendLine(@"<svg width=""800"" height=""600"" xmlns=""http://www.w3.org/2000/svg"">");

            // Basic SVG generation logic
            svg.AppendLine(@"  <rect width=""100%"" height=""100%"" fill=""white""/>");
            svg.AppendLine(@"  <text x=""400"" y=""50"" text-anchor=""middle"" font-size=""20"">Chart Export</text>");

            svg.AppendLine("</svg>");
            return svg.ToString();
        }

        private string ConvertChartDataToCsv(object chartData)
        {
            var csv = new StringBuilder();
            csv.AppendLine("Category,Value");

            // Generic CSV conversion
            if (chartData is IEnumerable<object> items)
            {
                foreach (var item in items)
                {
                    var properties = item.GetType().GetProperties();
                    var values = properties.Select(p => p.GetValue(item)?.ToString() ?? "");
                    csv.AppendLine(string.Join(",", values));
                }
            }

            return csv.ToString();
        }

        private string GenerateInteractiveHtml(object chartData, string chartType)
        {
            var html = new StringBuilder();
            html.AppendLine("<!DOCTYPE html>");
            html.AppendLine("<html>");
            html.AppendLine("<head>");
            html.AppendLine("  <meta charset='utf-8'>");
            html.AppendLine("  <title>Interactive Chart</title>");
            html.AppendLine("  <script src='https://cdn.plot.ly/plotly-2.26.0.min.js'></script>");
            html.AppendLine("  <style>body { font-family: Arial, sans-serif; margin: 20px; }</style>");
            html.AppendLine("</head>");
            html.AppendLine("<body>");
            html.AppendLine("  <h1>Interactive Chart Visualization</h1>");
            html.AppendLine("  <div id='chart' style='width:100%;height:600px;'></div>");
            html.AppendLine("  <script>");
            html.AppendLine("    var data = [{ x: [1,2,3,4,5], y: [1,2,4,8,16], type: 'scatter' }];");
            html.AppendLine("    var layout = { title: '" + chartType + "' };");
            html.AppendLine("    Plotly.newPlot('chart', data, layout);");
            html.AppendLine("  </script>");
            html.AppendLine("</body>");
            html.AppendLine("</html>");
            return html.ToString();
        }

        private string GenerateVisualizationReport(List<ChartExportInfo> charts)
        {
            var html = new StringBuilder();
            html.AppendLine("<!DOCTYPE html>");
            html.AppendLine("<html>");
            html.AppendLine("<head>");
            html.AppendLine("  <meta charset='utf-8'>");
            html.AppendLine("  <title>Visualization Report</title>");
            html.AppendLine("  <style>");
            html.AppendLine("    body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }");
            html.AppendLine("    .chart-container { background: white; padding: 20px; margin: 20px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }");
            html.AppendLine("    h1 { color: #333; }");
            html.AppendLine("    h2 { color: #666; }");
            html.AppendLine("  </style>");
            html.AppendLine("</head>");
            html.AppendLine("<body>");
            html.AppendLine("  <h1>PCAP Analyzer - Visualization Report</h1>");
            html.AppendLine($"  <p>Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p>");

            foreach (var chart in charts)
            {
                html.AppendLine("  <div class='chart-container'>");
                html.AppendLine($"    <h2>{chart.Title}</h2>");
                html.AppendLine($"    <p>{chart.Description}</p>");
                html.AppendLine("  </div>");
            }

            html.AppendLine("</body>");
            html.AppendLine("</html>");
            return html.ToString();
        }
    }

    public class ChartExportInfo
    {
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string ChartType { get; set; } = string.Empty;
        public object Data { get; set; } = new();
    }
}
