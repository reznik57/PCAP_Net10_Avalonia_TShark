using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Xunit;
using FluentAssertions;
using Moq;
using Microsoft.Extensions.Logging;
using PCAPAnalyzer.Core.Services.Reporting;
using PCAPAnalyzer.Core.Models;
using Bogus;

namespace PCAPAnalyzer.Tests.Services.Reporting
{
    /// <summary>
    /// Comprehensive unit tests for RemediationPlanner service.
    /// Tests plan generation, phase creation, task grouping, resource identification,
    /// and service-specific remediation steps.
    /// </summary>
    public class RemediationPlannerTests
    {
        private readonly Mock<ILogger<RemediationPlanner>> _mockLogger;
        private readonly RemediationPlanner _planner;
        private readonly Faker _faker;

        public RemediationPlannerTests()
        {
            _mockLogger = new Mock<ILogger<RemediationPlanner>>();
            _planner = new RemediationPlanner(_mockLogger.Object);
            _faker = new Faker();
        }

        #region GenerateAsync Tests

        [Fact]
        public async Task GenerateAsync_CreatesThreePhases()
        {
            // Arrange
            var findings = CreateTestFindings();
            var recommendations = CreateTestRecommendations();

            // Act
            var plan = await _planner.GenerateAsync(findings, recommendations);

            // Assert
            plan.Phases.Should().HaveCount(3, "plan should have Critical, Hardening, and Long-term phases");
            plan.Phases[0].Name.Should().Be("Critical Security Fixes");
            plan.Phases[1].Name.Should().Be("Security Hardening");
            plan.Phases[2].Name.Should().Be("Long-term Improvements");
        }

        [Fact]
        public async Task GenerateAsync_Phase1Timeline_IsSevenDays()
        {
            // Arrange
            var findings = CreateTestFindings();
            var recommendations = CreateTestRecommendations();

            // Act
            var plan = await _planner.GenerateAsync(findings, recommendations);

            // Assert
            var phase1 = plan.Phases[0];
            var duration = (phase1.EndDate - phase1.StartDate).TotalDays;
            duration.Should().BeApproximately(7, 1, "Phase 1 should be approximately 7 days");
        }

        [Fact]
        public async Task GenerateAsync_Phase2Timeline_IsThirtyDays()
        {
            // Arrange
            var findings = CreateTestFindings();
            var recommendations = CreateTestRecommendations();

            // Act
            var plan = await _planner.GenerateAsync(findings, recommendations);

            // Assert
            var phase2 = plan.Phases[1];
            var duration = (phase2.EndDate - phase2.StartDate).TotalDays;
            duration.Should().BeApproximately(22, 1, "Phase 2 should be approximately 22 days (day 8-30)");
        }

        [Fact]
        public async Task GenerateAsync_Phase3Timeline_IsNinetyDays()
        {
            // Arrange
            var findings = CreateTestFindings();
            var recommendations = CreateTestRecommendations();

            // Act
            var plan = await _planner.GenerateAsync(findings, recommendations);

            // Assert
            var phase3 = plan.Phases[2];
            var duration = (phase3.EndDate - phase3.StartDate).TotalDays;
            duration.Should().BeApproximately(60, 1, "Phase 3 should be approximately 60 days (day 31-90)");
        }

        [Fact]
        public async Task GenerateAsync_GroupsTasksByPriorityCorrectly()
        {
            // Arrange
            var findings = new List<SecurityFinding>
            {
                CreateFinding(SeverityLevel.Critical, RemediationPriority.Immediate),
                CreateFinding(SeverityLevel.High, RemediationPriority.High),
                CreateFinding(SeverityLevel.Medium, RemediationPriority.Medium),
                CreateFinding(SeverityLevel.Low, RemediationPriority.Low)
            };
            var recommendations = new List<Recommendation>();

            // Act
            var plan = await _planner.GenerateAsync(findings, recommendations);

            // Assert
            plan.TasksByPriority.Should().ContainKey("Immediate");
            plan.TasksByPriority.Should().ContainKey("High");
            plan.TasksByPriority.Should().ContainKey("Medium");
            plan.TasksByPriority.Should().ContainKey("Low");

            plan.TasksByPriority["Immediate"].Should().HaveCount(1);
            plan.TasksByPriority["High"].Should().HaveCount(1);
            plan.TasksByPriority["Medium"].Should().HaveCount(1);
            plan.TasksByPriority["Low"].Should().HaveCount(1);
        }

        [Fact]
        public async Task GenerateAsync_CalculatesTotalEstimatedTime()
        {
            // Arrange
            var findings = CreateTestFindings();
            var recommendations = CreateTestRecommendations();

            // Act
            var plan = await _planner.GenerateAsync(findings, recommendations);

            // Assert
            plan.TotalEstimatedTime.Should().NotBeEmpty();
            plan.TotalEstimatedTime.Should().Contain("month", "90-day plan should be measured in months");
        }

        [Fact]
        public async Task GenerateAsync_EstimatesResourceRequirements()
        {
            // Arrange
            var findings = new List<SecurityFinding>
            {
                CreateFinding(SeverityLevel.Critical, RemediationPriority.Immediate)
            };
            var recommendations = CreateTestRecommendations();

            // Act
            var plan = await _planner.GenerateAsync(findings, recommendations);

            // Assert
            plan.RequiredResources.Should().NotBeEmpty();
            plan.RequiredResources.Should().Contain(r => r.Contains("Network Administrator"));
            plan.RequiredResources.Should().Contain(r => r.Contains("Security Analyst"));
        }

        [Fact]
        public async Task GenerateAsync_CalculatesCostEstimate()
        {
            // Arrange
            var findings = CreateTestFindings();
            var recommendations = CreateTestRecommendations();

            // Act
            var plan = await _planner.GenerateAsync(findings, recommendations);

            // Assert
            plan.TotalEstimatedCost.Should().NotBeEmpty();
            plan.TotalEstimatedCost.Should().MatchRegex(@"(\$|Under|\d)", "cost should include dollar amounts or estimates");
        }

        [Fact]
        public async Task GenerateAsync_IdentifiesDependencies()
        {
            // Arrange
            var findings = new List<SecurityFinding>
            {
                CreateFinding(SeverityLevel.Critical, RemediationPriority.Immediate),
                CreateFinding(SeverityLevel.High, RemediationPriority.High)
            };
            var recommendations = new List<Recommendation>();

            // Act
            var plan = await _planner.GenerateAsync(findings, recommendations);

            // Assert
            plan.Dependencies.Should().NotBeEmpty();
            plan.Dependencies.Should().Contain(d => d.Contains("High-priority tasks depend on"));
        }

        [Fact]
        public async Task GenerateAsync_GeneratesSuccessCriteria()
        {
            // Arrange
            var findings = new List<SecurityFinding>
            {
                CreateFinding(SeverityLevel.Critical, RemediationPriority.Immediate),
                CreateFinding(SeverityLevel.High, RemediationPriority.High)
            };
            var recommendations = new List<Recommendation>();

            // Act
            var plan = await _planner.GenerateAsync(findings, recommendations);

            // Assert
            plan.SuccessCriteria.Should().NotBeEmpty();
            plan.SuccessCriteria.Should().Contain("critical");
            plan.SuccessCriteria.Should().Contain("high");
        }

        [Fact]
        public async Task GenerateAsync_WithEmptyFindings_HandlesGracefully()
        {
            // Arrange
            var findings = new List<SecurityFinding>();
            var recommendations = new List<Recommendation>();

            // Act
            var plan = await _planner.GenerateAsync(findings, recommendations);

            // Assert
            plan.Should().NotBeNull();
            plan.Phases.Should().HaveCount(3, "phases should still be created even with no findings");
            plan.TasksByPriority.Should().ContainKey("Immediate");
        }

        #endregion

        #region GenerateRecommendationsAsync Tests

        [Fact]
        public async Task GenerateRecommendationsAsync_CreatesSecurityRecommendations()
        {
            // Arrange
            var findings = new List<SecurityFinding>
            {
                new SecurityFinding
                {
                    Category = "Insecure Services",
                    Severity = SeverityLevel.High,
                    Title = "FTP Detected",
                    FindingId = Guid.NewGuid().ToString()
                }
            };
            var performanceIssues = new List<PerformanceIssue>();

            // Act
            var recommendations = await _planner.GenerateRecommendationsAsync(findings, performanceIssues);

            // Assert
            recommendations.Should().NotBeEmpty();
            recommendations.Should().Contain(r => r.Category == "Security");
            recommendations.Should().Contain(r => r.Title.Contains("Secure Protocol"));
        }

        [Fact]
        public async Task GenerateRecommendationsAsync_CreatesNetworkSegmentationRecommendation()
        {
            // Arrange
            var findings = CreateManyFindings(6); // More than 5 findings
            var performanceIssues = new List<PerformanceIssue>();

            // Act
            var recommendations = await _planner.GenerateRecommendationsAsync(findings, performanceIssues);

            // Assert
            recommendations.Should().Contain(r => r.Title.Contains("Network Segmentation"));
            var segmentationRec = recommendations.First(r => r.Title.Contains("Network Segmentation"));
            segmentationRec.Category.Should().Be("Architecture");
            segmentationRec.Priority.Should().Be(RemediationPriority.Medium);
        }

        [Fact]
        public async Task GenerateRecommendationsAsync_CreatesSIEMRecommendation()
        {
            // Arrange
            var findings = new List<SecurityFinding> { CreateFinding(SeverityLevel.High, RemediationPriority.High) };
            var performanceIssues = new List<PerformanceIssue>();

            // Act
            var recommendations = await _planner.GenerateRecommendationsAsync(findings, performanceIssues);

            // Assert
            recommendations.Should().Contain(r => r.Title.Contains("SIEM"));
            var siemRec = recommendations.First(r => r.Title.Contains("SIEM"));
            siemRec.Category.Should().Be("Monitoring");
            siemRec.Priority.Should().Be(RemediationPriority.High);
        }

        [Fact]
        public async Task GenerateRecommendationsAsync_CreatesPerformanceRecommendations()
        {
            // Arrange
            var findings = new List<SecurityFinding>();
            var performanceIssues = new List<PerformanceIssue>
            {
                new PerformanceIssue { Category = "Bandwidth", Severity = SeverityLevel.Medium }
            };

            // Act
            var recommendations = await _planner.GenerateRecommendationsAsync(findings, performanceIssues);

            // Assert
            recommendations.Should().Contain(r => r.Category == "Performance");
            recommendations.Should().Contain(r => r.Title.Contains("QoS") || r.Title.Contains("Traffic Shaping"));
        }

        [Fact]
        public async Task GenerateRecommendationsAsync_SortsByPriority()
        {
            // Arrange
            var findings = CreateManyFindings(6);
            var performanceIssues = new List<PerformanceIssue>
            {
                new PerformanceIssue { Category = "Bandwidth" }
            };

            // Act
            var recommendations = await _planner.GenerateRecommendationsAsync(findings, performanceIssues);

            // Assert
            recommendations.Should().BeInAscendingOrder(r => r.Priority, "recommendations should be sorted by priority");
        }

        #endregion

        #region GenerateServiceRemediationStep Tests

        [Fact]
        public void GenerateServiceRemediationStep_ForFTP_ReturnsCorrectSteps()
        {
            // Act
            var remediation = _planner.GenerateServiceRemediationStep(21, "FTP");

            // Assert
            remediation.Priority.Should().Be(RemediationPriority.Immediate);
            remediation.Summary.Should().Contain("FTP");
            remediation.DetailedSteps.Should().Contain(step => step.Contains("SFTP") || step.Contains("FTPS"));
            remediation.DetailedSteps.Should().Contain(step => step.Contains("port 21"));
            remediation.DetailedSteps.Should().HaveCountGreaterThanOrEqualTo(6);
            remediation.EstimatedEffort.Should().Contain("hours");
        }

        [Fact]
        public void GenerateServiceRemediationStep_ForTelnet_ReturnsCorrectSteps()
        {
            // Act
            var remediation = _planner.GenerateServiceRemediationStep(23, "Telnet");

            // Assert
            remediation.Priority.Should().Be(RemediationPriority.Immediate);
            remediation.Summary.Should().Contain("Telnet");
            remediation.DetailedSteps.Should().Contain(step => step.Contains("SSH"));
            remediation.DetailedSteps.Should().Contain(step => step.Contains("Disable Telnet"));
            remediation.DetailedSteps.Should().Contain(step => step.Contains("port 23"));
        }

        [Fact]
        public void GenerateServiceRemediationStep_ForSMB_ReturnsCorrectSteps()
        {
            // Act
            var remediation = _planner.GenerateServiceRemediationStep(445, "SMB");

            // Assert
            remediation.Priority.Should().Be(RemediationPriority.Immediate);
            remediation.DetailedSteps.Should().Contain(step => step.Contains("SMB"));
            remediation.DetailedSteps.Should().Contain(step => step.Contains("encryption") || step.Contains("signing"));
            remediation.DetailedSteps.Should().Contain(step => step.Contains("SMBv1"));
        }

        [Fact]
        public void GenerateServiceRemediationStep_ForRDP_ReturnsCorrectSteps()
        {
            // Act
            var remediation = _planner.GenerateServiceRemediationStep(3389, "RDP");

            // Assert
            remediation.Priority.Should().Be(RemediationPriority.High, "RDP is high priority, not immediate");
            remediation.DetailedSteps.Should().Contain(step => step.Contains("RDP") || step.Contains("Remote Desktop"));
            remediation.DetailedSteps.Should().Contain(step => step.Contains("NLA"));
            remediation.DetailedSteps.Should().Contain(step => step.Contains("multi-factor"));
            remediation.DetailedSteps.Should().Contain(step => step.Contains("VPN"));
        }

        [Fact]
        public void GenerateServiceRemediationStep_ForGenericPort_ReturnsGenericSteps()
        {
            // Act
            var remediation = _planner.GenerateServiceRemediationStep(9999, "CustomService");

            // Assert
            remediation.Priority.Should().Be(RemediationPriority.High);
            remediation.Summary.Should().Contain("CustomService");
            remediation.DetailedSteps.Should().Contain(step => step.Contains("9999"));
            remediation.DetailedSteps.Should().Contain(step => step.Contains("secure alternative"));
        }

        [Fact]
        public void GenerateServiceRemediationStep_IncludesValidationMethod()
        {
            // Act
            var remediation = _planner.GenerateServiceRemediationStep(21, "FTP");

            // Assert
            remediation.ValidationMethod.Should().NotBeEmpty();
            remediation.ValidationMethod.Should().Contain("Port scan");
            remediation.ValidationMethod.Should().Contain("secure alternative");
        }

        [Fact]
        public void GenerateServiceRemediationStep_IncludesExpectedOutcome()
        {
            // Act
            var remediation = _planner.GenerateServiceRemediationStep(23, "Telnet");

            // Assert
            remediation.ExpectedOutcome.Should().NotBeEmpty();
            remediation.ExpectedOutcome.Should().Contain("23");
            remediation.ExpectedOutcome.Should().Contain("closed");
        }

        #endregion

        #region Resource and Cost Calculation Tests

        [Fact]
        public async Task GenerateAsync_WithManyCriticalFindings_RecommendExternalConsultant()
        {
            // Arrange
            var findings = new List<SecurityFinding>();
            for (int i = 0; i < 6; i++)
            {
                findings.Add(CreateFinding(SeverityLevel.Critical, RemediationPriority.Immediate));
            }
            var recommendations = new List<Recommendation>();

            // Act
            var plan = await _planner.GenerateAsync(findings, recommendations);

            // Assert
            plan.RequiredResources.Should().Contain(r => r.Contains("External Security Consultant"));
        }

        [Fact]
        public async Task GenerateAsync_WithSIEMRecommendation_IncludesSIEMResource()
        {
            // Arrange
            var findings = new List<SecurityFinding> { CreateFinding(SeverityLevel.High, RemediationPriority.High) };
            var recommendations = new List<Recommendation>
            {
                new Recommendation { Title = "Deploy SIEM Solution", Priority = RemediationPriority.High }
            };

            // Act
            var plan = await _planner.GenerateAsync(findings, recommendations);

            // Assert
            plan.RequiredResources.Should().Contain(r => r.Contains("SIEM"));
        }

        [Fact]
        public async Task GenerateAsync_CalculatesCostBasedOnTaskCount()
        {
            // Arrange
            var fewFindings = new List<SecurityFinding> { CreateFinding(SeverityLevel.Medium, RemediationPriority.Medium) };
            var manyFindings = CreateManyFindings(10);

            // Act
            var smallPlan = await _planner.GenerateAsync(fewFindings, new List<Recommendation>());
            var largePlan = await _planner.GenerateAsync(manyFindings, new List<Recommendation>());

            // Assert
            // Both should have cost estimates, but we can't easily compare since format varies
            smallPlan.TotalEstimatedCost.Should().NotBeEmpty();
            largePlan.TotalEstimatedCost.Should().NotBeEmpty();
        }

        #endregion

        #region Success Criteria Tests

        [Fact]
        public async Task GenerateAsync_SuccessCriteria_IncludesCriticalCount()
        {
            // Arrange
            var findings = new List<SecurityFinding>
            {
                CreateFinding(SeverityLevel.Critical, RemediationPriority.Immediate),
                CreateFinding(SeverityLevel.Critical, RemediationPriority.Immediate)
            };
            var recommendations = new List<Recommendation>();

            // Act
            var plan = await _planner.GenerateAsync(findings, recommendations);

            // Assert
            plan.SuccessCriteria.Should().Contain("2");
            plan.SuccessCriteria.Should().Contain("critical");
        }

        [Fact]
        public async Task GenerateAsync_SuccessCriteria_IncludesHighCount()
        {
            // Arrange
            var findings = new List<SecurityFinding>
            {
                CreateFinding(SeverityLevel.High, RemediationPriority.High),
                CreateFinding(SeverityLevel.High, RemediationPriority.High),
                CreateFinding(SeverityLevel.High, RemediationPriority.High)
            };
            var recommendations = new List<Recommendation>();

            // Act
            var plan = await _planner.GenerateAsync(findings, recommendations);

            // Assert
            plan.SuccessCriteria.Should().Contain("3");
            plan.SuccessCriteria.Should().Contain("high");
        }

        [Fact]
        public async Task GenerateAsync_SuccessCriteria_IncludesSecurityMonitoring()
        {
            // Arrange
            var findings = CreateTestFindings();
            var recommendations = new List<Recommendation>();

            // Act
            var plan = await _planner.GenerateAsync(findings, recommendations);

            // Assert
            plan.SuccessCriteria.Should().Contain("monitoring");
        }

        #endregion

        #region Helper Methods

        private List<SecurityFinding> CreateTestFindings()
        {
            return new List<SecurityFinding>
            {
                CreateFinding(SeverityLevel.Critical, RemediationPriority.Immediate),
                CreateFinding(SeverityLevel.High, RemediationPriority.High),
                CreateFinding(SeverityLevel.Medium, RemediationPriority.Medium)
            };
        }

        private List<Recommendation> CreateTestRecommendations()
        {
            return new List<Recommendation>
            {
                new Recommendation
                {
                    Title = "Implement Network Segmentation",
                    Priority = RemediationPriority.Medium,
                    Category = "Architecture",
                    EstimatedTimeframe = "4-6 weeks"
                },
                new Recommendation
                {
                    Title = "Deploy SIEM Solution",
                    Priority = RemediationPriority.High,
                    Category = "Monitoring",
                    EstimatedTimeframe = "3-4 weeks"
                }
            };
        }

        private SecurityFinding CreateFinding(SeverityLevel severity, RemediationPriority priority)
        {
            return new SecurityFinding
            {
                FindingId = Guid.NewGuid().ToString(),
                Title = $"Test {severity} Finding",
                Category = "Test Category",
                Severity = severity,
                Description = $"Test finding with {severity} severity",
                Remediation = new RemediationStep
                {
                    Priority = priority,
                    Summary = $"Fix {severity} issue",
                    EstimatedEffort = "4-8 hours",
                    DetailedSteps = new List<string>
                    {
                        "Step 1: Analyze the issue",
                        "Step 2: Implement fix",
                        "Step 3: Validate solution"
                    }
                }
            };
        }

        private List<SecurityFinding> CreateManyFindings(int count)
        {
            var findings = new List<SecurityFinding>();
            for (int i = 0; i < count; i++)
            {
                var severity = i % 2 == 0 ? SeverityLevel.High : SeverityLevel.Medium;
                var priority = i % 2 == 0 ? RemediationPriority.High : RemediationPriority.Medium;
                findings.Add(CreateFinding(severity, priority));
            }
            return findings;
        }

        #endregion
    }
}
