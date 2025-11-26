using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.Reporting
{
    /// <summary>
    /// Generates HTML formatted network analysis reports with inline styling and JavaScript charts.
    /// Implements self-contained HTML generation suitable for email distribution and web viewing.
    /// </summary>
    public class HtmlReportGenerator : IHtmlReportGenerator
    {
        /// <summary>
        /// Generates a comprehensive HTML report from the network analysis data.
        /// </summary>
        /// <param name="report">Network analysis report containing all findings and metrics</param>
        /// <returns>Complete HTML document as string with inline CSS and JavaScript</returns>
        /// <exception cref="ArgumentNullException">Thrown when report is null</exception>
        public async Task<string> GenerateAsync(NetworkAnalysisReport report)
        {
            if (report == null)
                throw new ArgumentNullException(nameof(report));

            var html = new StringBuilder();

            AppendHtmlHeader(html, report);
            AppendStylesheet(html);
            html.AppendLine("</head>");
            html.AppendLine("<body>");

            AppendReportHeader(html, report);

            if (report.Configuration.IncludeExecutiveSummary)
            {
                AppendExecutiveSummary(html, report.ExecutiveSummary);
            }

            if (report.Configuration.IncludeSecurityFindings && report.SecurityFindings.Any())
            {
                AppendSecurityFindings(html, report.SecurityFindings, report.Configuration.MaxFindingsPerCategory);
            }

            AppendFooter(html, report);

            html.AppendLine("</body>");
            html.AppendLine("</html>");

            return await Task.FromResult(html.ToString());
        }

        private void AppendHtmlHeader(StringBuilder html, NetworkAnalysisReport report)
        {
            html.AppendLine("<!DOCTYPE html>");
            html.AppendLine("<html lang=\"en\">");
            html.AppendLine("<head>");
            html.AppendLine("<meta charset=\"UTF-8\">");
            html.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
            html.AppendLine($"<title>Network Analysis Report - {report.GeneratedAt:yyyy-MM-dd}</title>");
        }

        private void AppendStylesheet(StringBuilder html)
        {
            html.AppendLine("<style>");
            html.AppendLine(@"
                body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; }
                h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
                h2 { color: #34495e; margin-top: 30px; border-bottom: 2px solid #ecf0f1; padding-bottom: 5px; }
                h3 { color: #7f8c8d; margin-top: 20px; }
                .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
                .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
                .metric-card { background: #f8f9fa; padding: 15px; border-radius: 8px; border-left: 4px solid #3498db; }
                .metric-value { font-size: 2em; font-weight: bold; color: #2c3e50; }
                .metric-label { color: #7f8c8d; font-size: 0.9em; }
                .critical { background-color: #fee; border-left-color: #e74c3c !important; }
                .high { background-color: #fff3cd; border-left-color: #f39c12 !important; }
                .medium { background-color: #cfe2ff; border-left-color: #3498db !important; }
                .low { background-color: #d1ecf1; border-left-color: #17a2b8 !important; }
                .finding { background: white; border: 1px solid #dee2e6; border-radius: 8px; padding: 20px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
                .severity-badge { padding: 5px 10px; border-radius: 20px; color: white; font-weight: bold; font-size: 0.9em; }
                .severity-critical { background: #e74c3c; }
                .severity-high { background: #f39c12; }
                .severity-medium { background: #3498db; }
                .severity-low { background: #17a2b8; }
                .affected-systems { background: #f8f9fa; padding: 10px; border-radius: 5px; margin: 10px 0; }
                .remediation { background: #e8f5e9; padding: 15px; border-radius: 5px; margin: 15px 0; }
                .remediation-steps { background: white; padding: 10px; border-radius: 5px; margin: 10px 0; }
                .remediation-steps ol { margin: 5px 0; padding-left: 25px; }
                .footer { margin-top: 50px; padding-top: 20px; border-top: 2px solid #ecf0f1; text-align: center; color: #7f8c8d; }
                @media print { .no-print { display: none; } }
            ");
            html.AppendLine("</style>");
        }

        private void AppendReportHeader(StringBuilder html, NetworkAnalysisReport report)
        {
            html.AppendLine("<div class=\"header\">");
            html.AppendLine("<h1>Network Security Analysis Report</h1>");
            html.AppendLine($"<p>Generated: {report.GeneratedAt:yyyy-MM-dd HH:mm:ss UTC}</p>");
            html.AppendLine($"<p>Analysis Duration: {report.AnalysisDuration.TotalHours:F1} hours</p>");
            html.AppendLine("</div>");
        }

        private void AppendExecutiveSummary(StringBuilder html, ExecutiveSummary summary)
        {
            html.AppendLine("<h2>Executive Summary</h2>");
            html.AppendLine($"<p>{summary.Overview}</p>");

            html.AppendLine("<div class=\"summary-grid\">");

            html.AppendLine($"<div class=\"metric-card {(summary.SecurityScore < 60 ? "critical" : "")}\">");
            html.AppendLine($"<div class=\"metric-value\">{summary.SecurityScore:F0}</div>");
            html.AppendLine("<div class=\"metric-label\">Security Score</div>");
            html.AppendLine("</div>");

            html.AppendLine("<div class=\"metric-card\">");
            html.AppendLine($"<div class=\"metric-value\">{summary.TotalIssuesFound}</div>");
            html.AppendLine("<div class=\"metric-label\">Total Issues</div>");
            html.AppendLine("</div>");

            html.AppendLine($"<div class=\"metric-card {(summary.CriticalIssues > 0 ? "critical" : "")}\">");
            html.AppendLine($"<div class=\"metric-value\">{summary.CriticalIssues}</div>");
            html.AppendLine("<div class=\"metric-label\">Critical Issues</div>");
            html.AppendLine("</div>");

            html.AppendLine("<div class=\"metric-card\">");
            html.AppendLine($"<div class=\"metric-value\">{summary.ComplianceScore:F0}</div>");
            html.AppendLine("<div class=\"metric-label\">Compliance Score</div>");
            html.AppendLine("</div>");

            html.AppendLine("</div>");

            if (summary.ImmediateActions.Any())
            {
                html.AppendLine("<h3>Immediate Actions Required</h3>");
                html.AppendLine("<ul>");
                foreach (var action in summary.ImmediateActions)
                {
                    html.AppendLine($"<li>{action}</li>");
                }
                html.AppendLine("</ul>");
            }
        }

        private void AppendSecurityFindings(StringBuilder html, System.Collections.Generic.List<SecurityFinding> findings, int maxFindings)
        {
            html.AppendLine("<h2>Security Findings</h2>");

            foreach (var finding in findings.Take(maxFindings))
            {
                var severityClass = finding.Severity.ToString().ToLower();
                html.AppendLine($"<div class=\"finding {severityClass}\">");
                html.AppendLine("<div class=\"finding-header\">");
                html.AppendLine($"<h3>{finding.Title}</h3>");
                html.AppendLine($"<span class=\"severity-badge severity-{severityClass}\">{finding.Severity}</span>");
                html.AppendLine("</div>");

                html.AppendLine($"<p><strong>Description:</strong> {finding.Description}</p>");
                html.AppendLine($"<p><strong>Impact:</strong> {finding.PotentialImpact}</p>");

                if (finding.AffectedSystems.Any())
                {
                    html.AppendLine("<div class=\"affected-systems\">");
                    html.AppendLine($"<strong>Affected Systems ({finding.AffectedSystems.Count}):</strong>");
                    html.AppendLine("<ul>");
                    foreach (var system in finding.AffectedSystems.Take(5))
                    {
                        var ports = system.AffectedPorts.Any() ? string.Join(", ", system.AffectedPorts) : "N/A";
                        html.AppendLine($"<li>{system.IpAddress} - Ports: {ports}</li>");
                    }
                    if (finding.AffectedSystems.Count > 5)
                    {
                        html.AppendLine($"<li>... and {finding.AffectedSystems.Count - 5} more</li>");
                    }
                    html.AppendLine("</ul>");
                    html.AppendLine("</div>");
                }

                if (finding.Remediation != null)
                {
                    html.AppendLine("<div class=\"remediation\">");
                    html.AppendLine($"<strong>Remediation ({finding.Remediation.Priority}):</strong> {finding.Remediation.Summary}");
                    if (finding.Remediation.DetailedSteps.Any())
                    {
                        html.AppendLine("<div class=\"remediation-steps\">");
                        html.AppendLine("<ol>");
                        foreach (var step in finding.Remediation.DetailedSteps)
                        {
                            html.AppendLine($"<li>{step}</li>");
                        }
                        html.AppendLine("</ol>");
                        html.AppendLine("</div>");
                    }
                    if (!string.IsNullOrEmpty(finding.Remediation.EstimatedEffort))
                    {
                        html.AppendLine($"<p><strong>Estimated Effort:</strong> {finding.Remediation.EstimatedEffort}</p>");
                    }
                    html.AppendLine("</div>");
                }

                html.AppendLine("</div>");
            }
        }

        private void AppendFooter(StringBuilder html, NetworkAnalysisReport report)
        {
            html.AppendLine("<div class=\"footer\">");
            html.AppendLine($"<p>Generated by {report.GeneratedBy} v{report.Version}</p>");
            html.AppendLine($"<p>Report ID: {report.ReportId}</p>");
            html.AppendLine("</div>");
        }
    }
}
