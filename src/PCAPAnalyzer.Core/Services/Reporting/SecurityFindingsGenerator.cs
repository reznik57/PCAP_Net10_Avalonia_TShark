using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;
using Microsoft.Extensions.Logging;

namespace PCAPAnalyzer.Core.Services.Reporting
{
    /// <summary>
    /// Generates detailed security findings from network statistics and threats.
    /// Analyzes insecure services, suspicious patterns, and threat groupings.
    /// </summary>
    public class SecurityFindingsGenerator : ISecurityFindingsGenerator
    {
        private readonly ILogger<SecurityFindingsGenerator> _logger;

        public SecurityFindingsGenerator(ILogger<SecurityFindingsGenerator> logger)
        {
            ArgumentNullException.ThrowIfNull(logger);
            _logger = logger;
        }

        /// <summary>
        /// Generates comprehensive security findings from network statistics and threats.
        /// </summary>
        public async Task<List<SecurityFinding>> GenerateAsync(
            NetworkStatistics statistics,
            List<SecurityThreat> threats)
        {
            _logger.LogInformation("Generating security findings from {ThreatCount} threats", threats.Count);

            var findings = new List<SecurityFinding>();

            try
            {
                // Group threats by type for better organization
                var threatGroups = threats.GroupBy(t => t.Type);

                foreach (var group in threatGroups)
                {
                    var finding = await CreateThreatGroupFindingAsync(group, statistics);
                    findings.Add(finding);
                }

                // Add findings for insecure services
                var insecureServices = await AnalyzeInsecureServicesAsync(statistics);
                findings.AddRange(insecureServices);

                // Add findings for suspicious patterns
                var suspiciousPatterns = await AnalyzeSuspiciousPatternsAsync(statistics);
                findings.AddRange(suspiciousPatterns);

                // Sort by severity (ascending priority = descending severity) and risk score
                var sortedFindings = findings
                    .OrderBy(f => ReportingHelpers.GetSeverityPriority(f.Severity.ToString()))
                    .ThenByDescending(f => f.RiskScore)
                    .ToList();

                _logger.LogInformation("Generated {FindingCount} security findings", sortedFindings.Count);
                return sortedFindings;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating security findings");
                return findings;
            }
        }

        #region Threat Group Analysis

        /// <summary>
        /// Creates a security finding from a group of similar threats.
        /// </summary>
        private async Task<SecurityFinding> CreateThreatGroupFindingAsync(
            IGrouping<string, SecurityThreat> group,
            NetworkStatistics statistics)
        {
            var threats = group.ToList();

            var finding = new SecurityFinding
            {
                Title = $"{group.Key} Detected",
                Category = DetermineThreatCategory(group.Key),
                Severity = threats.Max(t => ConvertThreatSeverity(t.Severity)),
                OccurrenceCount = threats.Count,
                FirstDetected = threats.Min(t => t.DetectedAt),
                LastDetected = threats.Max(t => t.DetectedAt)
            };

            // Detailed description
            finding.Description = GenerateFindingDescription(group.Key, threats);

            // Technical details
            finding.TechnicalDetails = GenerateTechnicalDetails(threats);

            // Affected systems
            finding.AffectedSystems = IdentifyAffectedSystems(threats, statistics);

            // Potential impact
            finding.PotentialImpact = GeneratePotentialImpact(group.Key, finding.AffectedSystems.Count);

            // Root cause analysis
            finding.RootCause = AnalyzeRootCause(group.Key, threats);

            // Remediation steps
            finding.Remediation = GenerateRemediationSteps(group.Key, finding.AffectedSystems);

            // Evidence
            finding.Evidence = threats.Take(5).Select(t =>
                $"{t.DetectedAt:yyyy-MM-dd HH:mm:ss} - {t.SourceAddress} -> {t.DestinationAddress}"
            ).ToList();

            // Risk score calculation
            finding.RiskScore = CalculateRiskScore(finding.Severity, finding.AffectedSystems.Count, finding.OccurrenceCount);

            return await Task.FromResult(finding);
        }

        #endregion

        #region Insecure Services Analysis

        /// <summary>
        /// Analyzes network statistics to identify insecure service usage.
        /// </summary>
        public async Task<List<SecurityFinding>> AnalyzeInsecureServicesAsync(NetworkStatistics statistics)
        {
            var findings = new List<SecurityFinding>();

            foreach (var portUsage in statistics.TopPorts ?? new List<PortStatistics>())
            {
                if (!ReportingHelpers.IsInsecurePort(portUsage.Port))
                    continue;

                var affectedSystems = IdentifySystemsUsingPort(portUsage.Port, statistics);

                var finding = new SecurityFinding
                {
                    Title = $"Insecure Service: {ReportingHelpers.GetInsecurePortDescription(portUsage.Port)}",
                    Category = "Insecure Services",
                    Severity = DetermineServiceSeverity(portUsage.Port),
                    Description = $"The network analysis detected usage of {ReportingHelpers.GetInsecurePortDescription(portUsage.Port)} on port {portUsage.Port}. " +
                                $"This service is considered insecure and should be replaced with a secure alternative.",
                    TechnicalDetails = $"Port {portUsage.Port} was observed in {portUsage.PacketCount} packets. " +
                                     $"Affected systems: {string.Join(", ", affectedSystems.Select(s => s.IpAddress).Take(5))}",
                    AffectedSystems = affectedSystems,
                    PotentialImpact = GenerateServiceImpact(portUsage.Port),
                    RootCause = "Use of legacy or insecure protocols/services",
                    Remediation = GenerateServiceRemediation(portUsage.Port),
                    OccurrenceCount = (int)portUsage.PacketCount,
                    RiskScore = CalculateServiceRiskScore(portUsage.Port, affectedSystems.Count)
                };

                findings.Add(finding);
            }

            return await Task.FromResult(findings);
        }

        /// <summary>
        /// Identifies systems using a specific port.
        /// </summary>
        private List<AffectedSystem> IdentifySystemsUsingPort(int port, NetworkStatistics statistics)
        {
            var systemsUsingPort = statistics.TopConversations
                .Where(c => c.DestinationPort == port || c.SourcePort == port)
                .SelectMany(c => new[] { c.SourceAddress, c.DestinationAddress })
                .Distinct()
                .ToList();

            return systemsUsingPort.Select(ip => new AffectedSystem
            {
                IpAddress = ip,
                AffectedPorts = new List<int> { port },
                AffectedServices = new List<string> { ReportingHelpers.GetServiceName(port) },
                IsCriticalAsset = IsLikelyServer(ip, statistics)
            }).ToList();
        }

        #endregion

        #region Suspicious Patterns Analysis

        /// <summary>
        /// Analyzes network statistics for suspicious patterns like port scanning and data exfiltration.
        /// </summary>
        public async Task<List<SecurityFinding>> AnalyzeSuspiciousPatternsAsync(NetworkStatistics statistics)
        {
            var findings = new List<SecurityFinding>();

            // Check for port scanning based on conversations
            var portScanFindings = AnalyzePortScanningActivity(statistics);
            findings.AddRange(portScanFindings);

            // Check for data exfiltration patterns
            var exfiltrationFindings = AnalyzeDataExfiltrationPatterns(statistics);
            findings.AddRange(exfiltrationFindings);

            return await Task.FromResult(findings);
        }

        /// <summary>
        /// Detects port scanning activity in network traffic.
        /// </summary>
        private List<SecurityFinding> AnalyzePortScanningActivity(NetworkStatistics statistics)
        {
            var findings = new List<SecurityFinding>();

            var portScanners = statistics.TopConversations
                .GroupBy(c => c.SourceAddress)
                .Where(g => g.Select(c => c.DestinationPort).Distinct().Count() > 50)
                .ToList();

            foreach (var scanner in portScanners)
            {
                var affectedSystems = scanner
                    .GroupBy(c => c.DestinationAddress)
                    .Select(group => new AffectedSystem
                    {
                        IpAddress = group.Key,
                        AffectedPorts = group.Select(c => c.DestinationPort)
                                            .Distinct()
                                            .ToList()
                    })
                    .ToList();

                findings.Add(new SecurityFinding
                {
                    Title = "Port Scanning Activity Detected",
                    Category = "Reconnaissance",
                    Severity = SeverityLevel.High,
                    Description = $"IP address {scanner.Key} performed port scanning activity, " +
                                $"attempting to connect to {scanner.Select(c => c.DestinationPort).Distinct().Count()} different ports.",
                    AffectedSystems = affectedSystems,
                    PotentialImpact = "Reconnaissance activity may indicate preparation for an attack",
                    RootCause = "Lack of rate limiting and intrusion detection on network perimeter",
                    Remediation = new RemediationStep
                    {
                        Priority = RemediationPriority.Immediate,
                        Summary = "Block scanning source and investigate",
                        DetailedSteps = new List<string>
                        {
                            $"1. Immediately block IP address {scanner.Key} at the firewall",
                            "2. Review logs for any successful connections",
                            "3. Check if the source is internal (possible compromise) or external",
                            "4. Implement rate limiting on connection attempts",
                            "5. Deploy IDS/IPS rules to detect port scanning",
                            "6. Consider implementing port knocking or fail2ban"
                        },
                        EstimatedEffort = "4-6 hours",
                        RequiredSkills = "Network security, Firewall management",
                        ValidationMethod = "Verify scanning activity has stopped, No new scanning attempts detected"
                    },
                    OccurrenceCount = scanner.Count(),
                    RiskScore = 85.0
                });
            }

            return findings;
        }

        /// <summary>
        /// Detects potential data exfiltration patterns.
        /// </summary>
        private List<SecurityFinding> AnalyzeDataExfiltrationPatterns(NetworkStatistics statistics)
        {
            var findings = new List<SecurityFinding>();

            var largeTransfers = statistics.TopConversations
                .Where(c => c.ByteCount > 100_000_000) // 100MB+
                .Where(c => !ReportingHelpers.IsPrivateIP(c.DestinationAddress))
                .ToList();

            if (!largeTransfers.Any())
                return findings;

            var affectedSystems = largeTransfers.Select(c => new AffectedSystem
            {
                IpAddress = c.SourceAddress,
                AdditionalInfo = new Dictionary<string, string>
                {
                    { "Destination", c.DestinationAddress },
                    { "Data Transferred", ReportingHelpers.FormatBytes(c.ByteCount) },
                    { "Duration", ReportingHelpers.FormatDuration(c.Duration) }
                }
            }).ToList();

            findings.Add(new SecurityFinding
            {
                Title = "Potential Data Exfiltration",
                Category = "Data Loss",
                Severity = SeverityLevel.High,
                Description = $"Large data transfers to external IP addresses detected. " +
                            $"{largeTransfers.Count} flows exceeded 100MB to external destinations.",
                AffectedSystems = affectedSystems,
                PotentialImpact = "Sensitive data may have been exfiltrated from the network",
                RootCause = "Insufficient data loss prevention controls and egress filtering",
                Remediation = new RemediationStep
                {
                    Priority = RemediationPriority.Immediate,
                    Summary = "Investigate and implement DLP",
                    DetailedSteps = new List<string>
                    {
                        "1. Immediately investigate the large transfers",
                        "2. Verify if transfers were authorized",
                        "3. Implement Data Loss Prevention (DLP) policies",
                        "4. Configure alerts for large external transfers",
                        "5. Review and restrict outbound firewall rules",
                        "6. Implement cloud access security broker (CASB) if applicable"
                    },
                    EstimatedEffort = "8-16 hours",
                    RequiredSkills = "Security analysis, DLP implementation",
                    ValidationMethod = "Monitor external transfers, Verify DLP policies active"
                },
                OccurrenceCount = largeTransfers.Count,
                RiskScore = 90.0
            });

            return findings;
        }

        #endregion

        #region Service-Specific Remediation

        /// <summary>
        /// Generates service-specific remediation steps for insecure ports.
        /// </summary>
        private RemediationStep GenerateServiceRemediation(int port)
        {
            var remediation = new RemediationStep
            {
                Priority = port == 23 || port == 21 || port == 139 ? RemediationPriority.Immediate : RemediationPriority.High,
                Summary = $"Replace {ReportingHelpers.GetServiceName(port)} with secure alternative"
            };

            // Service-specific remediation steps
            remediation.DetailedSteps = port switch
            {
                21 => new List<string>
                {
                    "1. Identify all systems using FTP (port 21)",
                    "2. Deploy SFTP (SSH File Transfer Protocol) or FTPS (FTP over TLS)",
                    "3. Update all FTP clients to use secure protocols",
                    "4. Configure firewall rules to block port 21",
                    "5. Monitor for any remaining FTP traffic",
                    "6. Document the change in network configuration"
                },
                23 => new List<string>
                {
                    "1. Immediately identify all Telnet sessions",
                    "2. Deploy SSH (Secure Shell) on all systems",
                    "3. Configure SSH with key-based authentication",
                    "4. Disable Telnet service on all devices",
                    "5. Update firewall rules to block port 23",
                    "6. Audit all remote access methods"
                },
                139 or 445 => new List<string>
                {
                    "1. Identify all SMB/NetBIOS shares",
                    "2. Implement SMB signing and encryption",
                    "3. Disable SMBv1 protocol",
                    "4. Configure firewall to restrict SMB to internal network only",
                    "5. Implement network segmentation for file servers",
                    "6. Deploy DLP (Data Loss Prevention) for file shares"
                },
                3389 => new List<string>
                {
                    "1. Audit all RDP-enabled systems",
                    "2. Implement Network Level Authentication (NLA)",
                    "3. Configure RDP to use TLS 1.2 or higher",
                    "4. Deploy RD Gateway for external access",
                    "5. Implement multi-factor authentication",
                    "6. Use VPN for remote desktop access"
                },
                _ => new List<string>
                {
                    $"1. Identify all systems using port {port}",
                    $"2. Determine business need for {ReportingHelpers.GetServiceName(port)}",
                    "3. Research and implement secure alternative",
                    "4. Update firewall rules accordingly",
                    "5. Monitor for unauthorized usage",
                    "6. Document changes and update security policies"
                }
            };

            remediation.EstimatedEffort = port switch
            {
                21 or 23 => "4-8 hours per system",
                139 or 445 => "8-16 hours total",
                3389 => "2-4 hours per system",
                _ => "2-4 hours per system"
            };

            remediation.RequiredSkills = "Network administration, Security configuration";
            remediation.Tools = new List<string> { "SSH client/server", "Firewall management tools", "Network scanner" };
            remediation.ValidationMethod = "Port scan to verify service is disabled, Test secure alternative functionality";
            remediation.ExpectedOutcome = $"Port {port} closed on all systems, Secure alternative implemented and functional";

            return remediation;
        }

        #endregion

        #region Helper Methods

        private SeverityLevel ConvertThreatSeverity(ThreatSeverity severity)
        {
            return severity switch
            {
                ThreatSeverity.Critical => SeverityLevel.Critical,
                ThreatSeverity.High => SeverityLevel.High,
                ThreatSeverity.Medium => SeverityLevel.Medium,
                ThreatSeverity.Low => SeverityLevel.Low,
                _ => SeverityLevel.Info
            };
        }

        private string DetermineThreatCategory(string threatType)
        {
            return threatType switch
            {
                "Port Scan" => "Reconnaissance",
                "Malware" => "Malicious Activity",
                "DDoS" => "Availability Attack",
                "SQL Injection" => "Application Attack",
                "Brute Force" => "Authentication Attack",
                _ => "Security Threat"
            };
        }

        private string GenerateFindingDescription(string threatType, List<SecurityThreat> threats)
        {
            var count = threats.Count;
            var sources = threats.Select(t => t.SourceAddress).Distinct().Count();
            var targets = threats.Select(t => t.DestinationAddress).Distinct().Count();

            return $"Detected {count} instances of {threatType} from {sources} source(s) targeting {targets} system(s). " +
                   $"The activity occurred between {threats.Min(t => t.DetectedAt):yyyy-MM-dd HH:mm} and {threats.Max(t => t.DetectedAt):yyyy-MM-dd HH:mm}.";
        }

        private string GenerateTechnicalDetails(List<SecurityThreat> threats)
        {
            var sources = threats.Select(t => t.SourceAddress).Distinct();
            var targets = threats.Select(t => t.DestinationAddress).Distinct();

            return $"Unique sources: {sources.Count()}. " +
                   $"Unique targets: {targets.Count()}. " +
                   $"Peak activity: {threats.GroupBy(t => t.DetectedAt.Hour).OrderByDescending(g => g.Count()).FirstOrDefault()?.Key ?? 0}:00.";
        }

        private List<AffectedSystem> IdentifyAffectedSystems(List<SecurityThreat> threats, NetworkStatistics statistics)
        {
            var systems = new Dictionary<string, AffectedSystem>();

            foreach (var threat in threats)
            {
                if (!systems.ContainsKey(threat.DestinationAddress))
                {
                    systems[threat.DestinationAddress] = new AffectedSystem
                    {
                        IpAddress = threat.DestinationAddress,
                        AffectedPorts = new List<int>(),
                        AffectedServices = new List<string>(),
                        IsCriticalAsset = IsLikelyServer(threat.DestinationAddress, statistics)
                    };
                }
            }

            return systems.Values.ToList();
        }

        private string GeneratePotentialImpact(string threatType, int affectedSystemCount)
        {
            return threatType switch
            {
                "Port Scan" => $"Reconnaissance of {affectedSystemCount} systems may lead to targeted attacks",
                "Malware" => $"Potential compromise of {affectedSystemCount} systems with data theft or ransomware risk",
                "DDoS" => $"Service disruption affecting {affectedSystemCount} systems and business operations",
                "SQL Injection" => "Database compromise with potential data breach and data manipulation",
                "Brute Force" => "Unauthorized access to user accounts and privileged systems",
                _ => $"Security breach affecting {affectedSystemCount} systems"
            };
        }

        private string AnalyzeRootCause(string threatType, List<SecurityThreat> threats)
        {
            return threatType switch
            {
                "Port Scan" => "Lack of rate limiting and intrusion detection on network perimeter",
                "Malware" => "Inadequate endpoint protection and user security awareness",
                "DDoS" => "Insufficient DDoS protection and traffic filtering",
                "SQL Injection" => "Unvalidated user input in web applications",
                "Brute Force" => "Weak password policies and lack of account lockout mechanisms",
                _ => "Security control gaps and insufficient monitoring"
            };
        }

        private RemediationStep GenerateRemediationSteps(string threatType, List<AffectedSystem> affectedSystems)
        {
            var step = new RemediationStep
            {
                Priority = affectedSystems.Any(s => s.IsCriticalAsset) ? RemediationPriority.Immediate : RemediationPriority.High
            };

            switch (threatType)
            {
                case "Port Scan":
                    step.Summary = "Implement network access controls and monitoring";
                    step.DetailedSteps = new List<string>
                    {
                        "1. Configure firewall to block scanning source IPs",
                        "2. Implement rate limiting on connection attempts",
                        "3. Deploy IDS/IPS with port scan detection rules",
                        "4. Enable logging on all network devices",
                        "5. Configure alerts for scanning activity",
                        "6. Review and minimize exposed services"
                    };
                    step.EstimatedEffort = "4-6 hours";
                    break;

                case "Malware":
                    step.Summary = "Contain infection and strengthen endpoint security";
                    step.DetailedSteps = new List<string>
                    {
                        "1. Immediately isolate infected systems",
                        "2. Run full antivirus scans on all systems",
                        "3. Update antivirus signatures",
                        "4. Check for indicators of compromise (IoCs)",
                        "5. Review system logs for suspicious activity",
                        "6. Implement application whitelisting",
                        "7. Enhance email security filtering"
                    };
                    step.EstimatedEffort = "8-16 hours";
                    break;

                default:
                    step.Summary = "Implement security controls";
                    step.DetailedSteps = new List<string>
                    {
                        "1. Review and patch affected systems",
                        "2. Implement appropriate security controls",
                        "3. Configure monitoring and alerting",
                        "4. Update security policies",
                        "5. Conduct security assessment"
                    };
                    step.EstimatedEffort = "4-8 hours";
                    break;
            }

            step.RequiredSkills = "Network security, System administration";
            step.ValidationMethod = "Security scan to verify remediation effectiveness";

            return step;
        }

        private double CalculateRiskScore(SeverityLevel severity, int affectedSystems, int occurrences)
        {
            double baseScore = severity switch
            {
                SeverityLevel.Critical => 90,
                SeverityLevel.High => 70,
                SeverityLevel.Medium => 40,
                SeverityLevel.Low => 20,
                _ => 10
            };

            // Adjust for scope
            if (affectedSystems > 10) baseScore += 10;
            else if (affectedSystems > 5) baseScore += 5;

            // Adjust for frequency
            if (occurrences > 100) baseScore += 10;
            else if (occurrences > 50) baseScore += 5;

            return Math.Min(100, baseScore);
        }

        private SeverityLevel DetermineServiceSeverity(int port)
        {
            return port switch
            {
                23 or 21 or 139 => SeverityLevel.Critical, // Telnet, FTP, NetBIOS
                445 or 3389 or 135 => SeverityLevel.High,  // SMB, RDP, RPC
                1433 or 3306 or 5432 => SeverityLevel.High, // Databases
                _ => SeverityLevel.Medium
            };
        }

        private string GenerateServiceImpact(int port)
        {
            return port switch
            {
                23 => "Credentials transmitted in plaintext can be intercepted",
                21 => "Files and credentials transmitted without encryption",
                139 or 445 => "File shares exposed, potential for ransomware spread",
                3389 => "Remote desktop exposed, high risk of unauthorized access",
                1433 or 3306 or 5432 => "Database exposed, risk of data breach",
                _ => "Service may be exploited by attackers"
            };
        }

        private double CalculateServiceRiskScore(int port, int affectedSystems)
        {
            double baseScore = port switch
            {
                23 or 21 => 80,
                139 or 445 => 75,
                3389 => 70,
                1433 or 3306 or 5432 => 85,
                _ => 50
            };

            if (affectedSystems > 5) baseScore += 10;

            return Math.Min(100, baseScore);
        }

        private bool IsLikelyServer(string ip, NetworkStatistics statistics)
        {
            // Check if IP receives many connections (likely a server)
            var incomingConnections = statistics.TopConversations?.Count(c => c.DestinationAddress == ip) ?? 0;
            return incomingConnections > 50;
        }

        #endregion
    }
}
