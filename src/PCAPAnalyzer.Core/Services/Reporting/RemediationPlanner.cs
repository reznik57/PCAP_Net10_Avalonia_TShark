using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;
using Microsoft.Extensions.Logging;

namespace PCAPAnalyzer.Core.Services.Reporting
{
    /// <summary>
    /// Generates comprehensive remediation plans from security findings and recommendations.
    /// Organizes tasks by priority, creates phases, and estimates resource requirements.
    /// </summary>
    public class RemediationPlanner : IRemediationPlanner
    {
        private readonly ILogger<RemediationPlanner> _logger;

        public RemediationPlanner(ILogger<RemediationPlanner> logger)
        {
            ArgumentNullException.ThrowIfNull(logger);
            _logger = logger;
        }

        /// <summary>
        /// Generates a complete remediation plan from security findings and recommendations.
        /// </summary>
        public async Task<RemediationPlan> GenerateAsync(
            List<SecurityFinding> findings,
            List<Recommendation> recommendations)
        {
            _logger.LogInformation("Generating remediation plan from {FindingCount} findings and {RecCount} recommendations",
                findings.Count, recommendations.Count);

            var plan = new RemediationPlan();

            try
            {
                // Group tasks by priority
                plan.TasksByPriority = GroupTasksByPriority(findings);

                // Create execution phases
                plan.Phases = CreateRemediationPhases(findings, recommendations);

                // Calculate total estimated time
                plan.TotalEstimatedTime = CalculateTotalTime(plan.Phases);

                // Identify required resources
                plan.RequiredResources = IdentifyRequiredResources(findings, recommendations);

                // Estimate total cost
                plan.TotalEstimatedCost = CalculateEstimatedCost(plan.Phases);

                // Identify dependencies
                plan.Dependencies = IdentifyTaskDependencies(plan.TasksByPriority);

                // Generate success criteria
                plan.SuccessCriteria = string.Join("; ", GenerateSuccessCriteria(findings));

                _logger.LogInformation("Generated remediation plan with {PhaseCount} phases and {TaskCount} tasks",
                    plan.Phases.Count, plan.TasksByPriority.Values.Sum(t => t.Count));

                return await Task.FromResult(plan);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating remediation plan");
                return plan;
            }
        }

        #region Task Grouping

        /// <summary>
        /// Groups remediation tasks by priority level.
        /// </summary>
        private Dictionary<string, List<RemediationTask>> GroupTasksByPriority(List<SecurityFinding> findings)
        {
            var tasksByPriority = new Dictionary<string, List<RemediationTask>>
            {
                ["Immediate"] = new List<RemediationTask>(),
                ["High"] = new List<RemediationTask>(),
                ["Medium"] = new List<RemediationTask>(),
                ["Low"] = new List<RemediationTask>()
            };

            foreach (var finding in findings)
            {
                var task = new RemediationTask
                {
                    Name = $"Fix: {finding.Title}",
                    Description = finding.Remediation.Summary,
                    Priority = finding.Remediation.Priority,
                    EstimatedEffort = finding.Remediation.EstimatedEffort,
                    RelatedFindings = new List<string> { finding.FindingId },
                    Status = "Not Started"
                };

                // Add to appropriate priority bucket
                var priorityKey = finding.Remediation.Priority switch
                {
                    RemediationPriority.Immediate => "Immediate",
                    RemediationPriority.High => "High",
                    RemediationPriority.Medium => "Medium",
                    RemediationPriority.Low => "Low",
                    _ => "Low"
                };

                tasksByPriority[priorityKey].Add(task);
            }

            return tasksByPriority;
        }

        #endregion

        #region Phase Creation

        /// <summary>
        /// Creates multi-phase remediation plan with clear timelines and deliverables.
        /// </summary>
        private List<RemediationPhase> CreateRemediationPhases(
            List<SecurityFinding> findings,
            List<Recommendation> recommendations)
        {
            var phases = new List<RemediationPhase>();

            // Phase 1: Critical Security Fixes (Immediate priority items)
            var phase1Tasks = findings
                .Where(f => f.Remediation.Priority == RemediationPriority.Immediate)
                .Select(f => new RemediationTask
                {
                    Name = $"Fix: {f.Title}",
                    Description = f.Remediation.Summary,
                    Priority = RemediationPriority.Immediate,
                    EstimatedEffort = f.Remediation.EstimatedEffort,
                    RelatedFindings = new List<string> { f.FindingId },
                    Status = "Not Started"
                }).ToList();

            phases.Add(new RemediationPhase
            {
                PhaseNumber = 1,
                Name = "Critical Security Fixes",
                Description = "Address immediate security vulnerabilities that pose critical risk",
                StartDate = DateTime.UtcNow,
                EndDate = DateTime.UtcNow.AddDays(7),
                Tasks = phase1Tasks,
                Deliverables = new List<string>
                {
                    "All critical vulnerabilities patched or mitigated",
                    "Insecure services disabled or replaced",
                    "Emergency firewall rules implemented",
                    "Incident response procedures activated"
                },
                SuccessCriteria = "No critical-severity findings remain; All immediate-priority tasks completed; Security scan shows no critical vulnerabilities"
            });

            // Phase 2: Security Hardening (High priority items)
            var phase2Tasks = findings
                .Where(f => f.Remediation.Priority == RemediationPriority.High)
                .Select(f => new RemediationTask
                {
                    Name = $"Harden: {f.Title}",
                    Description = f.Remediation.Summary,
                    Priority = RemediationPriority.High,
                    EstimatedEffort = f.Remediation.EstimatedEffort,
                    RelatedFindings = new List<string> { f.FindingId },
                    Status = "Not Started"
                }).ToList();

            phases.Add(new RemediationPhase
            {
                PhaseNumber = 2,
                Name = "Security Hardening",
                Description = "Implement security best practices and harden systems",
                StartDate = DateTime.UtcNow.AddDays(8),
                EndDate = DateTime.UtcNow.AddDays(30),
                Tasks = phase2Tasks,
                Deliverables = new List<string>
                {
                    "Secure protocols implemented for all administrative access",
                    "Network segmentation completed",
                    "Access controls strengthened",
                    "Security monitoring enhanced"
                },
                SuccessCriteria = "All high-priority findings remediated; Secure protocols in use for remote access; Network segmentation validated"
            });

            // Phase 3: Long-term Improvements (Based on recommendations)
            var phase3Tasks = recommendations.Select(r => new RemediationTask
            {
                Name = r.Title,
                Description = r.Description,
                Priority = r.Priority,
                EstimatedEffort = r.EstimatedTimeframe,
                Status = "Not Started"
            }).ToList();

            // Add medium priority findings to phase 3
            var mediumFindings = findings
                .Where(f => f.Remediation.Priority == RemediationPriority.Medium)
                .Select(f => new RemediationTask
                {
                    Name = $"Improve: {f.Title}",
                    Description = f.Remediation.Summary,
                    Priority = RemediationPriority.Medium,
                    EstimatedEffort = f.Remediation.EstimatedEffort,
                    RelatedFindings = new List<string> { f.FindingId },
                    Status = "Not Started"
                });

            phase3Tasks.AddRange(mediumFindings);

            phases.Add(new RemediationPhase
            {
                PhaseNumber = 3,
                Name = "Long-term Improvements",
                Description = "Implement strategic security enhancements and process improvements",
                StartDate = DateTime.UtcNow.AddDays(31),
                EndDate = DateTime.UtcNow.AddDays(90),
                Tasks = phase3Tasks,
                Deliverables = new List<string>
                {
                    "SIEM deployment and configuration completed",
                    "Security policies updated and documented",
                    "Staff security awareness training completed",
                    "Vulnerability management program established",
                    "Regular security assessments scheduled"
                },
                SuccessCriteria = "All medium-priority findings addressed; Security monitoring fully operational; Documented security policies and procedures; Regular security assessment schedule established"
            });

            return phases;
        }

        /// <summary>
        /// Generates recommendations based on security findings and performance issues.
        /// </summary>
        public async Task<List<Recommendation>> GenerateRecommendationsAsync(
            List<SecurityFinding> findings,
            List<PerformanceIssue> performanceIssues)
        {
            var recommendations = new List<Recommendation>();

            // Security recommendations based on findings
            if (findings.Any(f => f.Category == "Insecure Services"))
            {
                recommendations.Add(new Recommendation
                {
                    Priority = RemediationPriority.High,
                    Category = "Security",
                    Title = "Implement Secure Protocol Standards",
                    Description = "Replace all insecure protocols with encrypted alternatives across the network",
                    Benefit = "Eliminate plaintext credential transmission and protect sensitive data in transit",
                    Implementation = "Phase-based replacement starting with most critical systems",
                    EstimatedTimeframe = "2-4 weeks",
                    ExpectedImprovement = 40,
                    RelatedFindings = findings.Where(f => f.Category == "Insecure Services").Select(f => f.FindingId).ToList()
                });
            }

            // Network segmentation recommendation
            if (findings.Count > 5)
            {
                recommendations.Add(new Recommendation
                {
                    Priority = RemediationPriority.Medium,
                    Category = "Architecture",
                    Title = "Implement Network Segmentation",
                    Description = "Deploy VLANs and firewall rules to segment the network by function and security level",
                    Benefit = "Limit lateral movement in case of breach, improve performance, and simplify management",
                    Implementation = "Design segmentation strategy, deploy VLANs, configure inter-VLAN routing with security policies",
                    EstimatedTimeframe = "4-6 weeks",
                    ExpectedImprovement = 60
                });
            }

            // Monitoring recommendation
            recommendations.Add(new Recommendation
            {
                Priority = RemediationPriority.High,
                Category = "Monitoring",
                Title = "Deploy Security Information and Event Management (SIEM)",
                Description = "Implement centralized logging and real-time security monitoring",
                Benefit = "Early threat detection, compliance reporting, and incident response capability",
                Implementation = "Select SIEM solution, deploy collectors, configure alerting rules",
                EstimatedTimeframe = "3-4 weeks",
                ExpectedImprovement = 50
            });

            // Performance-based recommendations
            if (performanceIssues.Any(p => p.Category == "Bandwidth"))
            {
                recommendations.Add(new Recommendation
                {
                    Priority = RemediationPriority.Medium,
                    Category = "Performance",
                    Title = "Implement Traffic Shaping and QoS",
                    Description = "Configure Quality of Service policies to prioritize critical traffic",
                    Benefit = "Improved response times for business-critical applications",
                    Implementation = "Identify critical traffic, configure QoS policies, test and validate",
                    EstimatedTimeframe = "1-2 weeks",
                    ExpectedImprovement = 30
                });
            }

            return await Task.FromResult(recommendations.OrderBy(r => r.Priority).ToList());
        }

        #endregion

        #region Resource Planning

        /// <summary>
        /// Identifies required resources (personnel, tools, budget) for remediation.
        /// </summary>
        private List<string> IdentifyRequiredResources(
            List<SecurityFinding> findings,
            List<Recommendation> recommendations)
        {
            var resources = new HashSet<string>();

            // Personnel resources
            if (findings.Any(f => f.Remediation.Priority == RemediationPriority.Immediate))
            {
                resources.Add("Network Administrator (Full-time, 2-4 weeks)");
                resources.Add("Security Analyst (Full-time, 2-4 weeks)");
            }

            if (findings.Any())
            {
                resources.Add("System Administrator (Part-time, duration of plan)");
            }

            if (findings.Count(f => f.Severity == SeverityLevel.Critical) > 5)
            {
                resources.Add("External Security Consultant (As needed)");
            }

            // Tools and software
            if (findings.Any(f => f.Category.Contains("Services", StringComparison.OrdinalIgnoreCase)))
            {
                resources.Add("SSH/SFTP server software licenses");
            }

            if (recommendations.Any(r => r.Title.Contains("SIEM", StringComparison.OrdinalIgnoreCase)))
            {
                resources.Add("SIEM solution (license and deployment)");
            }

            if (findings.Any(f => f.Category.Contains("Scanning", StringComparison.OrdinalIgnoreCase)))
            {
                resources.Add("IDS/IPS solution deployment");
            }

            // Training and documentation
            resources.Add("Security awareness training program");
            resources.Add("Technical documentation and runbooks");

            return resources.ToList();
        }

        /// <summary>
        /// Calculates total estimated time across all phases.
        /// </summary>
        private string CalculateTotalTime(List<RemediationPhase> phases)
        {
            if (!phases.Any())
                return "Unknown";

            var startDate = phases.Min(p => p.StartDate);
            var endDate = phases.Max(p => p.EndDate);
            var totalDays = (endDate - startDate).TotalDays;

            if (totalDays <= 7)
                return "1 week";
            if (totalDays <= 30)
                return $"{Math.Ceiling(totalDays / 7)} weeks";
            if (totalDays <= 90)
                return $"{Math.Ceiling(totalDays / 30)} months";

            return $"{Math.Ceiling(totalDays / 30)} months";
        }

        /// <summary>
        /// Estimates total cost based on effort and resources.
        /// </summary>
        private string CalculateEstimatedCost(List<RemediationPhase> phases)
        {
            var totalTasks = phases.Sum(p => p.Tasks.Count);

            // Rough estimation based on task count and complexity
            var estimatedHours = totalTasks * 6; // Average 6 hours per task
            var laborCost = estimatedHours * 150; // $150/hour blended rate

            // Add software/licensing costs
            var softwareCost = 10000; // Estimated for SIEM, IDS/IPS, etc.

            var totalCost = laborCost + softwareCost;

            if (totalCost < 10000)
                return "Under $10,000";
            if (totalCost < 50000)
                return $"${totalCost / 1000}K - ${(totalCost + 10000) / 1000}K";
            if (totalCost < 100000)
                return $"${totalCost / 1000}K - $100K";

            return "Over $100,000 (detailed estimate required)";
        }

        #endregion

        #region Dependencies and Success Criteria

        /// <summary>
        /// Identifies dependencies between remediation tasks.
        /// </summary>
        private List<string> IdentifyTaskDependencies(Dictionary<string, List<RemediationTask>> tasksByPriority)
        {
            var dependencies = new List<string>();

            // Critical tasks must complete before high-priority tasks
            if (tasksByPriority["Immediate"].Any() && tasksByPriority["High"].Any())
            {
                dependencies.Add("High-priority tasks depend on completion of immediate-priority fixes");
            }

            // Network segmentation may be required before other hardening
            var hasSegmentationTask = tasksByPriority.Values
                .SelectMany(t => t)
                .Any(t => t.Name.Contains("segmentation", StringComparison.OrdinalIgnoreCase));

            if (hasSegmentationTask)
            {
                dependencies.Add("Network segmentation should be completed before deploying monitoring solutions");
            }

            // Firewall rules should be updated before deploying new services
            var hasFirewallTask = tasksByPriority.Values
                .SelectMany(t => t)
                .Any(t => t.Description.Contains("firewall", StringComparison.OrdinalIgnoreCase));

            if (hasFirewallTask)
            {
                dependencies.Add("Firewall rule updates should precede new service deployments");
            }

            return dependencies.Any() ? dependencies : new List<string> { "No critical task dependencies identified" };
        }

        /// <summary>
        /// Generates success criteria for the overall remediation plan.
        /// </summary>
        private List<string> GenerateSuccessCriteria(List<SecurityFinding> findings)
        {
            var criteria = new List<string>();

            var criticalCount = findings.Count(f => f.Severity == SeverityLevel.Critical);
            var highCount = findings.Count(f => f.Severity == SeverityLevel.High);

            if (criticalCount > 0)
            {
                criteria.Add($"All {criticalCount} critical-severity findings fully remediated");
            }

            if (highCount > 0)
            {
                criteria.Add($"All {highCount} high-severity findings addressed");
            }

            criteria.Add("Security scan shows improved security posture (50%+ reduction in findings)");
            criteria.Add("All insecure protocols replaced with secure alternatives");
            criteria.Add("Security monitoring and alerting operational");
            criteria.Add("Incident response procedures tested and documented");
            criteria.Add("Management approval and sign-off obtained");

            return criteria;
        }

        /// <summary>
        /// Generates service-specific remediation steps for insecure ports.
        /// </summary>
        public RemediationStep GenerateServiceRemediationStep(int port, string serviceName)
        {
            var remediation = new RemediationStep
            {
                // Critical attack vectors (FTP, Telnet, NetBIOS, SMB) require immediate attention
                // SMB (445) is a primary vector for ransomware (WannaCry, NotPetya, etc.)
                Priority = port == 23 || port == 21 || port == 139 || port == 445 ? RemediationPriority.Immediate : RemediationPriority.High,
                Summary = $"Replace {serviceName} with secure alternative"
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
                    $"2. Determine business need for {serviceName}",
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
    }
}
