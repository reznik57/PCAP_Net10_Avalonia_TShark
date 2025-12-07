using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services.Reporting;

namespace PCAPAnalyzer.Core.Services
{
    /// <summary>
    /// Main orchestrator service for network analysis report generation.
    /// Coordinates specialized services to produce comprehensive security and network analysis reports.
    /// </summary>
    public interface IReportGeneratorService
    {
        /// <summary>
        /// Generates a comprehensive network analysis report from statistics and threats.
        /// </summary>
        /// <param name="statistics">Network statistics containing packet analysis data.</param>
        /// <param name="threats">List of detected security threats.</param>
        /// <param name="configuration">Report configuration specifying sections to include.</param>
        /// <param name="reportType">Type of report to generate (Technical, Executive, Compliance).</param>
        /// <returns>Complete network analysis report with all requested sections.</returns>
        Task<NetworkAnalysisReport> GenerateReportAsync(
            NetworkStatistics statistics,
            List<SecurityThreat> threats,
            ReportConfiguration configuration,
            ReportType reportType = ReportType.Technical);

        /// <summary>
        /// Exports a report to HTML format.
        /// </summary>
        /// <param name="report">The report to export.</param>
        /// <returns>HTML-formatted report as string.</returns>
        Task<string> ExportToHtmlAsync(NetworkAnalysisReport report);

        /// <summary>
        /// Exports a report to PDF format.
        /// </summary>
        /// <param name="report">The report to export.</param>
        /// <returns>PDF document as byte array.</returns>
        Task<byte[]> ExportToPdfAsync(NetworkAnalysisReport report);

        /// <summary>
        /// Exports a report to JSON format.
        /// </summary>
        /// <param name="report">The report to export.</param>
        /// <returns>JSON-formatted report as string.</returns>
        Task<string> ExportToJsonAsync(NetworkAnalysisReport report);
    }

    /// <summary>
    /// Orchestrator implementation for network analysis report generation.
    /// Delegates specialized tasks to dedicated services while coordinating overall report assembly.
    /// </summary>
    public sealed class ReportGeneratorService : IReportGeneratorService
    {
        private readonly ISecurityFindingsGenerator _securityFindingsGenerator;
        private readonly IRemediationPlanner _remediationPlanner;
        private readonly IHtmlReportGenerator _htmlReportGenerator;
        private readonly IJsonReportGenerator _jsonReportGenerator;
        private readonly IPdfReportGenerator _pdfReportGenerator;
        private readonly ILogger<ReportGeneratorService> _logger;

        /// <summary>
        /// Initializes a new instance of the ReportGeneratorService with injected dependencies.
        /// </summary>
        /// <param name="securityFindingsGenerator">Service for generating security findings.</param>
        /// <param name="remediationPlanner">Service for creating remediation plans.</param>
        /// <param name="htmlReportGenerator">Service for HTML export.</param>
        /// <param name="jsonReportGenerator">Service for JSON export.</param>
        /// <param name="pdfReportGenerator">Service for PDF export.</param>
        /// <param name="logger">Logger for diagnostics.</param>
        public ReportGeneratorService(
            ISecurityFindingsGenerator securityFindingsGenerator,
            IRemediationPlanner remediationPlanner,
            IHtmlReportGenerator htmlReportGenerator,
            IJsonReportGenerator jsonReportGenerator,
            IPdfReportGenerator pdfReportGenerator,
            ILogger<ReportGeneratorService> logger)
        {
            ArgumentNullException.ThrowIfNull(securityFindingsGenerator);
            ArgumentNullException.ThrowIfNull(remediationPlanner);
            ArgumentNullException.ThrowIfNull(htmlReportGenerator);
            ArgumentNullException.ThrowIfNull(jsonReportGenerator);
            ArgumentNullException.ThrowIfNull(pdfReportGenerator);
            ArgumentNullException.ThrowIfNull(logger);
            _securityFindingsGenerator = securityFindingsGenerator;
            _remediationPlanner = remediationPlanner;
            _htmlReportGenerator = htmlReportGenerator;
            _jsonReportGenerator = jsonReportGenerator;
            _pdfReportGenerator = pdfReportGenerator;
            _logger = logger;
        }

        /// <summary>
        /// Generates a comprehensive network analysis report by coordinating specialized services.
        /// </summary>
        public async Task<NetworkAnalysisReport> GenerateReportAsync(
            NetworkStatistics statistics,
            List<SecurityThreat> threats,
            ReportConfiguration configuration,
            ReportType reportType = ReportType.Technical)
        {
            _logger.LogInformation("Starting report generation for {PacketCount} packets and {ThreatCount} threats",
                statistics.TotalPackets, threats.Count);

            try
            {
                var report = new NetworkAnalysisReport
                {
                    Type = reportType,
                    Configuration = configuration,
                    AnalysisDuration = statistics.Duration,
                    GeneratedAt = DateTime.UtcNow,
                    ReportId = ReportingHelpers.GenerateReportId(),
                    GeneratedBy = "PCAP Analyzer",
                    Version = "1.0.0"
                };

                // Generate Executive Summary
                if (configuration.IncludeExecutiveSummary)
                {
                    _logger.LogDebug("Generating executive summary");
                    report.ExecutiveSummary = GenerateExecutiveSummary(statistics, threats);
                }

                // Generate Network Overview
                _logger.LogDebug("Generating network overview");
                report.NetworkOverview = GenerateNetworkOverview(statistics);

                // Delegate Security Findings to specialized service
                if (configuration.IncludeSecurityFindings)
                {
                    _logger.LogDebug("Delegating security findings generation");
                    report.SecurityFindings = await _securityFindingsGenerator.GenerateAsync(statistics, threats);
                }

                // Generate Performance Issues
                if (configuration.IncludePerformanceAnalysis)
                {
                    _logger.LogDebug("Generating performance issues");
                    report.PerformanceIssues = GeneratePerformanceIssues(statistics);
                }

                // Generate Compliance Violations
                if (configuration.IncludeComplianceCheck)
                {
                    _logger.LogDebug("Generating compliance violations");
                    report.ComplianceViolations = GenerateComplianceViolations(statistics, threats);
                }

                // Delegate Recommendations to remediation planner
                if (configuration.IncludeRecommendations)
                {
                    _logger.LogDebug("Delegating recommendations generation");
                    report.Recommendations = await _remediationPlanner.GenerateRecommendationsAsync(
                        report.SecurityFindings,
                        report.PerformanceIssues);
                }

                // Generate Risk Assessment
                _logger.LogDebug("Generating risk assessment");
                report.RiskAssessment = GenerateRiskAssessment(report.SecurityFindings, threats);

                // Delegate Remediation Plan to specialized service
                _logger.LogDebug("Delegating remediation plan generation");
                report.RemediationPlan = await _remediationPlanner.GenerateAsync(
                    report.SecurityFindings,
                    report.Recommendations);

                // Generate Technical Details if requested
                if (configuration.IncludeTechnicalDetails)
                {
                    _logger.LogDebug("Generating technical details");
                    report.TechnicalDetails = GenerateTechnicalDetails(statistics, threats);
                }

                _logger.LogInformation("Report generation completed successfully with {FindingCount} security findings",
                    report.SecurityFindings?.Count ?? 0);

                return report;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating network analysis report");
                throw;
            }
        }

        #region Export Methods

        /// <summary>
        /// Exports the report to HTML format using the specialized HTML generator.
        /// </summary>
        public async Task<string> ExportToHtmlAsync(NetworkAnalysisReport report)
        {
            _logger.LogInformation("Exporting report {ReportId} to HTML", report.ReportId);
            try
            {
                return await _htmlReportGenerator.GenerateAsync(report);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error exporting report to HTML");
                throw;
            }
        }

        /// <summary>
        /// Exports the report to PDF format using the specialized PDF generator.
        /// </summary>
        public async Task<byte[]> ExportToPdfAsync(NetworkAnalysisReport report)
        {
            _logger.LogInformation("Exporting report {ReportId} to PDF", report.ReportId);
            try
            {
                return await _pdfReportGenerator.GenerateAsync(report);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error exporting report to PDF");
                throw;
            }
        }

        /// <summary>
        /// Exports the report to JSON format using the specialized JSON generator.
        /// </summary>
        public async Task<string> ExportToJsonAsync(NetworkAnalysisReport report)
        {
            _logger.LogInformation("Exporting report {ReportId} to JSON", report.ReportId);
            try
            {
                return await _jsonReportGenerator.GenerateAsync(report);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error exporting report to JSON");
                throw;
            }
        }

        #endregion

        #region Executive Summary Generation

        /// <summary>
        /// Generates an executive summary with high-level metrics and key findings.
        /// </summary>
        private ExecutiveSummary GenerateExecutiveSummary(NetworkStatistics statistics, List<SecurityThreat> threats)
        {
            var summary = new ExecutiveSummary
            {
                TotalPacketsAnalyzed = (int)statistics.TotalPackets,
                CriticalIssues = threats.Count(t => t.Severity == ThreatSeverity.Critical),
                HighPriorityIssues = threats.Count(t => t.Severity == ThreatSeverity.High),
                TotalIssuesFound = threats.Count
            };

            // Calculate security score (100 - penalties)
            double securityScore = 100;
            securityScore -= summary.CriticalIssues * 15;
            securityScore -= summary.HighPriorityIssues * 8;
            securityScore -= threats.Count(t => t.Severity == ThreatSeverity.Medium) * 3;
            summary.SecurityScore = Math.Max(0, securityScore);

            // Calculate compliance and performance scores
            summary.ComplianceScore = CalculateComplianceScore(statistics, threats);
            summary.PerformanceScore = CalculatePerformanceScore(statistics);

            // Determine overall risk level
            summary.OverallRiskLevel = DetermineOverallRiskLevel(summary);

            // Generate key findings and immediate actions
            summary.KeyFindings = GenerateKeyFindings(statistics, threats);
            summary.ImmediateActions = GenerateImmediateActions(threats);
            summary.BusinessImpact = GenerateBusinessImpact(summary.OverallRiskLevel, threats);
            summary.EstimatedRemediationEffort = EstimateRemediationEffort(threats);

            summary.Overview = $"Analysis of {statistics.TotalPackets:N0} network packets revealed {summary.TotalIssuesFound} security issues, " +
                              $"including {summary.CriticalIssues} critical and {summary.HighPriorityIssues} high-priority findings. " +
                              $"The overall network security score is {summary.SecurityScore:F1}/100 with a {summary.OverallRiskLevel} risk level.";

            return summary;
        }

        /// <summary>
        /// Determines the overall risk level based on security metrics.
        /// </summary>
        private string DetermineOverallRiskLevel(ExecutiveSummary summary)
        {
            if (summary.CriticalIssues > 0 || summary.SecurityScore < 40)
                return "Critical";
            if (summary.HighPriorityIssues > 3 || summary.SecurityScore < 60)
                return "High";
            if (summary.SecurityScore < 80)
                return "Medium";
            return "Low";
        }

        #endregion

        #region Network Overview Generation

        /// <summary>
        /// Generates a comprehensive network overview with topology and traffic patterns.
        /// </summary>
        private NetworkOverview GenerateNetworkOverview(NetworkStatistics statistics)
        {
            var overview = new NetworkOverview
            {
                TotalDevices = statistics.AllUniqueIPs.Count,
                TotalConnections = statistics.TopConversations?.Count ?? 0,
                TotalBandwidth = statistics.TotalBytes
            };

            // Protocol distribution
            overview.ProtocolDistribution = statistics.ProtocolStats.ToDictionary(
                kvp => kvp.Key,
                kvp => (int)kvp.Value.PacketCount
            );

            // Service distribution based on ports
            overview.ServiceDistribution = GenerateServiceDistribution(statistics);

            // Top talkers
            overview.TopTalkers = GenerateTopTalkers(statistics);

            // Network segments
            overview.Segments = IdentifyNetworkSegments(statistics);

            // Critical devices
            overview.CriticalDevices = IdentifyCriticalDevices(statistics);

            // External connections
            overview.ExternalConnections = statistics.AllUniqueIPs
                .Where(ip => !ReportingHelpers.IsPrivateIP(ip))
                .Take(20)
                .ToList();

            return overview;
        }

        /// <summary>
        /// Generates top talker information from network statistics.
        /// </summary>
        private List<TopTalker> GenerateTopTalkers(NetworkStatistics statistics)
        {
            var topTalkers = new List<TopTalker>();

            foreach (var source in statistics.TopSources.Take(10))
            {
                topTalkers.Add(new TopTalker
                {
                    IpAddress = source.Address,
                    Hostname = source.Organization ?? "Unknown",
                    BytesSent = source.ByteCount,
                    BytesReceived = 0,
                    ConnectionCount = (int)source.PacketCount
                });
            }

            return topTalkers;
        }

        /// <summary>
        /// Generates service distribution from port usage statistics.
        /// </summary>
        private Dictionary<string, int> GenerateServiceDistribution(NetworkStatistics statistics)
        {
            var services = new Dictionary<string, int>();

            foreach (var port in statistics.TopPorts ?? new List<PortStatistics>())
            {
                var serviceName = ReportingHelpers.GetServiceName(port.Port);
                if (!string.IsNullOrEmpty(serviceName))
                {
                    if (!services.ContainsKey(serviceName))
                        services[serviceName] = 0;
                    services[serviceName] += (int)port.PacketCount;
                }
            }

            return services.OrderByDescending(s => s.Value).Take(10).ToDictionary(s => s.Key, s => s.Value);
        }

        /// <summary>
        /// Identifies network segments from IP address patterns.
        /// </summary>
        private List<NetworkSegmentInfo> IdentifyNetworkSegments(NetworkStatistics statistics)
        {
            var segments = new List<NetworkSegmentInfo>();

            var subnets = statistics.AllUniqueIPs
                .Where(ReportingHelpers.IsPrivateIP)
                .Select(GetSubnet)
                .Distinct()
                .ToList();

            foreach (var subnet in subnets)
            {
                var ipsInSubnet = statistics.AllUniqueIPs
                    .Where(ip => GetSubnet(ip) == subnet)
                    .Distinct()
                    .Count();

                segments.Add(new NetworkSegmentInfo
                {
                    Name = $"Subnet {subnet}",
                    Subnet = subnet,
                    DeviceCount = ipsInSubnet,
                    SecurityLevel = "Unknown"
                });
            }

            return segments;
        }

        /// <summary>
        /// Identifies critical devices (servers, gateways) based on connection patterns.
        /// </summary>
        private List<DeviceInfo> IdentifyCriticalDevices(NetworkStatistics statistics)
        {
            var servers = statistics.TopConversations
                .GroupBy(c => c.DestinationAddress)
                .Where(g => g.Count() > 100)
                .Select(g => new DeviceInfo
                {
                    IpAddress = g.Key,
                    Type = "Server",
                    Criticality = "High",
                    Services = g.Select(c => ReportingHelpers.GetServiceName(c.DestinationPort))
                               .Where(s => !string.IsNullOrEmpty(s))
                               .Distinct()
                               .ToList()
                })
                .ToList();

            return servers;
        }

        #endregion

        #region Performance Issues Generation

        /// <summary>
        /// Identifies and categorizes network performance issues.
        /// </summary>
        private List<PerformanceIssue> GeneratePerformanceIssues(NetworkStatistics statistics)
        {
            var issues = new List<PerformanceIssue>();

            // Check for bandwidth saturation
            var highBandwidthFlows = statistics.TopConversations
                .Where(c => c.PacketsPerSecond > 10000)
                .ToList();

            if (highBandwidthFlows.Count > 5)
            {
                issues.Add(new PerformanceIssue
                {
                    Title = "Bandwidth Saturation Detected",
                    Category = "Bandwidth",
                    Severity = SeverityLevel.Medium,
                    Description = $"{highBandwidthFlows.Count} connections consuming excessive bandwidth",
                    AffectedSystems = highBandwidthFlows.Select(c => new AffectedSystem
                    {
                        IpAddress = c.SourceAddress,
                        AdditionalInfo = new Dictionary<string, string>
                        {
                            { "Packet Rate", $"{c.PacketsPerSecond:F0} pps" },
                            { "Total Data", ReportingHelpers.FormatBytes(c.ByteCount) }
                        }
                    }).ToList(),
                    Impact = "Network congestion, slow response times for other users",
                    Remediation = new RemediationStep
                    {
                        Priority = RemediationPriority.Medium,
                        Summary = "Implement bandwidth management",
                        DetailedSteps = new List<string>
                        {
                            "1. Identify and classify high-bandwidth applications",
                            "2. Implement traffic shaping policies",
                            "3. Configure QoS for critical services",
                            "4. Consider network segmentation",
                            "5. Evaluate need for bandwidth upgrade",
                            "6. Implement caching for frequently accessed content"
                        }
                    }
                });
            }

            return issues;
        }

        #endregion

        #region Compliance Violations Generation

        /// <summary>
        /// Identifies compliance violations based on regulatory standards.
        /// </summary>
        private List<ComplianceViolation> GenerateComplianceViolations(NetworkStatistics statistics, List<SecurityThreat> threats)
        {
            var violations = new List<ComplianceViolation>();

            // PCI-DSS checks
            var hasTelnet = statistics.TopPorts?.Any(p => p.Port == 23) ?? false;
            var hasFTP = statistics.TopPorts?.Any(p => p.Port == 21) ?? false;

            if (hasTelnet || hasFTP)
            {
                violations.Add(new ComplianceViolation
                {
                    Standard = "PCI-DSS",
                    Requirement = "2.3 - Encrypt all non-console administrative access",
                    Description = "Unencrypted administrative protocols (Telnet/FTP) detected",
                    Severity = SeverityLevel.Critical,
                    Evidence = "Telnet or FTP traffic observed in network capture",
                    ComplianceImpact = "Failure to meet PCI-DSS requirements may result in fines and loss of payment processing privileges",
                    Remediation = new RemediationStep
                    {
                        Priority = RemediationPriority.Immediate,
                        Summary = "Replace with encrypted protocols",
                        DetailedSteps = new List<string>
                        {
                            "1. Replace Telnet with SSH",
                            "2. Replace FTP with SFTP or FTPS",
                            "3. Document all administrative access methods",
                            "4. Implement logging for all administrative access"
                        }
                    },
                    DueDate = DateTime.UtcNow.AddDays(30)
                });
            }

            // HIPAA checks
            var hasHTTP = statistics.TopPorts?.Any(p => p.Port == 80 || p.Port == 8080) ?? false;
            if (hasHTTP)
            {
                violations.Add(new ComplianceViolation
                {
                    Standard = "HIPAA",
                    Requirement = "164.312(e)(1) - Transmission Security",
                    Description = "Unencrypted HTTP traffic detected which may contain PHI",
                    Severity = SeverityLevel.High,
                    Evidence = "HTTP traffic on ports 80/8080 observed",
                    ComplianceImpact = "Potential HIPAA violation if PHI is transmitted unencrypted",
                    Remediation = new RemediationStep
                    {
                        Priority = RemediationPriority.High,
                        Summary = "Implement HTTPS for all web traffic",
                        DetailedSteps = new List<string>
                        {
                            "1. Deploy SSL/TLS certificates on all web servers",
                            "2. Configure HTTPS redirect for all HTTP traffic",
                            "3. Implement HSTS (HTTP Strict Transport Security)",
                            "4. Audit all web applications for PHI handling"
                        }
                    },
                    DueDate = DateTime.UtcNow.AddDays(60)
                });
            }

            return violations;
        }

        #endregion

        #region Risk Assessment Generation

        /// <summary>
        /// Generates a comprehensive risk assessment with scores and mitigation strategies.
        /// </summary>
        private RiskAssessment GenerateRiskAssessment(List<SecurityFinding> findings, List<SecurityThreat> threats)
        {
            var assessment = new RiskAssessment();

            // Calculate overall risk score
            double riskScore = 0;
            riskScore += findings.Count(f => f.Severity == SeverityLevel.Critical) * 25;
            riskScore += findings.Count(f => f.Severity == SeverityLevel.High) * 15;
            riskScore += findings.Count(f => f.Severity == SeverityLevel.Medium) * 8;
            riskScore += findings.Count(f => f.Severity == SeverityLevel.Low) * 3;

            assessment.OverallRiskScore = Math.Min(100, riskScore);

            // Determine risk level
            assessment.RiskLevel = assessment.OverallRiskScore switch
            {
                >= 75 => "Critical",
                >= 50 => "High",
                >= 25 => "Medium",
                _ => "Low"
            };

            // Category scores
            assessment.CategoryScores = new Dictionary<string, double>
            {
                { "Network Security", CalculateCategoryScore(findings, "Security") },
                { "Data Protection", CalculateCategoryScore(findings, "Data") },
                { "Access Control", CalculateCategoryScore(findings, "Access") },
                { "Compliance", CalculateCategoryScore(findings, "Compliance") }
            };

            // Risk factors
            assessment.RiskFactors = GenerateRiskFactors(findings);

            // Risk trend
            assessment.RiskTrend = "Stable";

            // Mitigation strategies
            assessment.MitigationStrategies = new List<string>
            {
                "Implement defense-in-depth security architecture",
                "Deploy continuous security monitoring",
                "Establish incident response procedures",
                "Regular security assessments and penetration testing",
                "Security awareness training for all staff"
            };

            assessment.BusinessImpactAnalysis = GenerateBusinessImpactAnalysis(assessment.RiskLevel, findings);

            return assessment;
        }

        /// <summary>
        /// Generates risk factors from security findings.
        /// </summary>
        private List<RiskFactor> GenerateRiskFactors(List<SecurityFinding> findings)
        {
            return new List<RiskFactor>
            {
                new RiskFactor
                {
                    Name = "Unencrypted Services",
                    Score = findings.Count(f => f.Category == "Insecure Services") * 10,
                    Description = "Multiple unencrypted services expose sensitive data",
                    Mitigation = "Implement encryption for all network services"
                },
                new RiskFactor
                {
                    Name = "External Exposure",
                    Score = findings.Count(f => f.Description.Contains("external", StringComparison.OrdinalIgnoreCase)) * 15,
                    Description = "Services exposed to external networks",
                    Mitigation = "Implement proper firewall rules and network segmentation"
                }
            };
        }

        #endregion

        #region Technical Details Generation

        /// <summary>
        /// Generates detailed technical information including packet samples and flow data.
        /// </summary>
        private TechnicalDetails GenerateTechnicalDetails(NetworkStatistics statistics, List<SecurityThreat> threats)
        {
            var details = new TechnicalDetails();

            // Add packet samples for critical threats
            var criticalThreats = threats.Where(t => t.Severity == ThreatSeverity.Critical).Take(5);
            details.PacketSamples["Critical Threats"] = criticalThreats.Select(t => new PacketSample
            {
                PacketNumber = 0,
                Timestamp = t.DetectedAt,
                Source = t.SourceAddress,
                Destination = t.DestinationAddress,
                Protocol = "TCP",
                Summary = t.Description
            }).ToList();

            // Add suspicious flows
            details.SuspiciousFlows = statistics.TopConversations
                .Where(c => c.ByteCount > 50_000_000 || c.PacketCount > 10000)
                .Take(10)
                .Select(c => new NetworkFlow
                {
                    FlowId = Guid.NewGuid().ToString(),
                    SourceIP = c.SourceAddress,
                    SourcePort = c.SourcePort,
                    DestinationIP = c.DestinationAddress,
                    DestinationPort = c.DestinationPort,
                    Protocol = c.Protocol,
                    BytesTransferred = c.ByteCount,
                    PacketCount = (int)c.PacketCount,
                    StartTime = c.StartTime,
                    EndTime = c.EndTime,
                    Reason = c.ByteCount > 50_000_000 ? "Large data transfer" : "High packet count"
                }).ToList();

            return details;
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// Calculates compliance score based on protocol usage and threats.
        /// </summary>
        private double CalculateComplianceScore(NetworkStatistics statistics, List<SecurityThreat> threats)
        {
            double score = 100;

            var insecurePorts = statistics.TopPorts?.Where(p =>
                p.Port == 23 || p.Port == 21 || p.Port == 80
            ) ?? new List<PortStatistics>();

            foreach (var port in insecurePorts)
            {
                if (port.Port == 23 || port.Port == 21) score -= 20;
                if (port.Port == 80) score -= 10;
            }

            score -= threats.Count(t => t.Severity == ThreatSeverity.Critical) * 10;
            score -= threats.Count(t => t.Severity == ThreatSeverity.High) * 5;

            return Math.Max(0, score);
        }

        /// <summary>
        /// Calculates performance score from network metrics.
        /// </summary>
        private double CalculatePerformanceScore(NetworkStatistics statistics)
        {
            double score = 100;

            if (statistics.TopConversations?.Count > 1000) score -= 10;

            var anomalyCount = statistics.AnomaliesPerSecondTimeSeries?.Count(a => a.Value > 0) ?? 0;
            if (anomalyCount > 100) score -= 15;

            return Math.Max(0, score);
        }

        /// <summary>
        /// Generates key findings summary list.
        /// </summary>
        private List<string> GenerateKeyFindings(NetworkStatistics statistics, List<SecurityThreat> threats)
        {
            var findings = new List<string>();

            if (threats.Any(t => t.Severity == ThreatSeverity.Critical))
                findings.Add($"{threats.Count(t => t.Severity == ThreatSeverity.Critical)} critical security vulnerabilities require immediate attention");

            var insecurePorts = statistics.TopPorts?.Where(p => ReportingHelpers.IsInsecurePort(p.Port)).Select(p => p.Port).ToList() ?? new List<int>();
            if (insecurePorts.Any())
                findings.Add($"{insecurePorts.Count} insecure services detected on the network");

            if (statistics.UniqueCountries > 10)
                findings.Add($"International traffic to {statistics.UniqueCountries} countries detected");

            return findings;
        }

        /// <summary>
        /// Generates immediate actions list based on threats.
        /// </summary>
        private List<string> GenerateImmediateActions(List<SecurityThreat> threats)
        {
            var actions = new List<string>();

            if (threats.Any(t => t.Type == "Port Scan"))
                actions.Add("Block port scanning sources at firewall");

            if (threats.Any(t => t.Type == "Malware"))
                actions.Add("Isolate infected systems and run malware scans");

            if (threats.Any(t => t.Severity == ThreatSeverity.Critical))
                actions.Add("Patch critical vulnerabilities within 24 hours");

            actions.Add("Review and update firewall rules");
            actions.Add("Enable logging on all critical systems");

            return actions.Take(5).ToList();
        }

        /// <summary>
        /// Generates business impact statement based on risk level.
        /// </summary>
        private string GenerateBusinessImpact(string riskLevel, List<SecurityThreat> threats)
        {
            return riskLevel switch
            {
                "Critical" => "Immediate risk of data breach or service disruption. Business operations may be severely impacted. Regulatory compliance at risk.",
                "High" => "Significant security gaps that could lead to data loss or unauthorized access. Potential for financial and reputational damage.",
                "Medium" => "Security posture needs improvement. Risk of minor incidents or compliance issues.",
                _ => "Security posture is acceptable with minor improvements recommended."
            };
        }

        /// <summary>
        /// Estimates remediation effort based on threat counts.
        /// </summary>
        private string EstimateRemediationEffort(List<SecurityThreat> threats)
        {
            var criticalCount = threats.Count(t => t.Severity == ThreatSeverity.Critical);
            var highCount = threats.Count(t => t.Severity == ThreatSeverity.High);

            var totalHours = criticalCount * 8 + highCount * 4 + threats.Count * 2;

            if (totalHours > 160)
                return "4-6 weeks with dedicated team";
            if (totalHours > 80)
                return "2-3 weeks with dedicated resources";
            if (totalHours > 40)
                return "1-2 weeks";

            return "Less than 1 week";
        }

        /// <summary>
        /// Calculates risk score for a specific finding category.
        /// </summary>
        private double CalculateCategoryScore(List<SecurityFinding> findings, string category)
        {
            var categoryFindings = findings.Where(f => f.Category.Contains(category, StringComparison.OrdinalIgnoreCase));

            if (!categoryFindings.Any()) return 100;

            double score = 100;
            score -= categoryFindings.Count(f => f.Severity == SeverityLevel.Critical) * 20;
            score -= categoryFindings.Count(f => f.Severity == SeverityLevel.High) * 10;
            score -= categoryFindings.Count(f => f.Severity == SeverityLevel.Medium) * 5;

            return Math.Max(0, score);
        }

        /// <summary>
        /// Generates business impact analysis for risk assessment.
        /// </summary>
        private string GenerateBusinessImpactAnalysis(string riskLevel, List<SecurityFinding> findings)
        {
            var criticalFindings = findings.Where(f => f.Severity == SeverityLevel.Critical).ToList();

            if (criticalFindings.Any())
            {
                return $"Critical security vulnerabilities present an immediate threat to business operations. " +
                       $"{criticalFindings.Count} critical issues could result in data breach, service disruption, or regulatory violations. " +
                       $"Estimated potential loss: High. Immediate action required.";
            }

            return riskLevel switch
            {
                "High" => "Significant security gaps could impact business continuity and customer trust. Risk of financial loss and reputational damage.",
                "Medium" => "Moderate security issues present manageable risk. Proactive remediation recommended to prevent escalation.",
                _ => "Security posture is acceptable. Continue monitoring and regular assessments."
            };
        }

        /// <summary>
        /// Extracts subnet identifier from IP address.
        /// </summary>
        private string GetSubnet(string ip)
        {
            var parts = ip.Split('.');
            if (parts.Length != 4) return "Unknown";

            return $"{parts[0]}.{parts[1]}.{parts[2]}.0/24";
        }

        #endregion
    }
}
