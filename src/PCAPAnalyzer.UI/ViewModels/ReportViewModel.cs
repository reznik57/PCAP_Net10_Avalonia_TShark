using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Input;
using Avalonia.Platform.Storage;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.ViewModels
{
    public partial class ReportViewModel : ObservableObject
    {
        private IDispatcherService Dispatcher => _dispatcher ??= App.Services?.GetService<IDispatcherService>()
            ?? throw new InvalidOperationException("IDispatcherService not registered");
        private IDispatcherService? _dispatcher;

        private readonly IReportGeneratorService _reportService;
        private NetworkStatistics? _currentStatistics;
        private List<SecurityThreat> _currentThreats = new();
        
        [ObservableProperty] private NetworkAnalysisReport? _currentReport;
        [ObservableProperty] private bool _isGenerating;
        [ObservableProperty] private string _generationStatus = "Ready to generate report";
        [ObservableProperty] private bool _hasReport;
        
        // Report configuration
        [ObservableProperty] private ReportType _selectedReportType = ReportType.Technical;
        [ObservableProperty] private bool _includeExecutiveSummary = true;
        [ObservableProperty] private bool _includeSecurityFindings = true;
        [ObservableProperty] private bool _includePerformanceAnalysis = true;
        [ObservableProperty] private bool _includeComplianceCheck = true;
        [ObservableProperty] private bool _includeRecommendations = true;
        [ObservableProperty] private bool _includeTechnicalDetails = false;
        [ObservableProperty] private bool _includeRawData = false;
        [ObservableProperty] private bool _includePacketSamples = false;
        [ObservableProperty] private bool _includeNetworkDiagrams = true;
        [ObservableProperty] private bool _includeRemediationTimeline = true;
        [ObservableProperty] private bool _includeCostEstimates = false;
        [ObservableProperty] private int _maxFindingsPerCategory = 10;
        [ObservableProperty] private SeverityLevel _minimumSeverity = SeverityLevel.Low;
        
        // Report sections for preview
        [ObservableProperty] private string _executiveSummaryText = "";
        [ObservableProperty] private ObservableCollection<SecurityFindingViewModel> _securityFindings = new();
        [ObservableProperty] private ObservableCollection<RecommendationViewModel> _recommendations = new();
        [ObservableProperty] private string _riskAssessmentText = "";
        [ObservableProperty] private ObservableCollection<RemediationPhaseViewModel> _remediationPhases = new();
        
        // Statistics
        [ObservableProperty] private int _totalFindings;
        [ObservableProperty] private int _criticalFindings;
        [ObservableProperty] private int _highFindings;
        [ObservableProperty] private int _mediumFindings;
        [ObservableProperty] private int _lowFindings;
        [ObservableProperty] private double _securityScore;
        [ObservableProperty] private double _complianceScore;
        [ObservableProperty] private string _overallRiskLevel = "Unknown";
        [ObservableProperty] private string _reportGeneratedTime = "";
        
        public ObservableCollection<ReportType> ReportTypes { get; } = new()
        {
            ReportType.Executive,
            ReportType.Technical,
            ReportType.Compliance,
            ReportType.Security,
            ReportType.Performance,
            ReportType.Custom
        };
        
        public ObservableCollection<SeverityLevel> SeverityLevels { get; } = new()
        {
            SeverityLevel.Critical,
            SeverityLevel.High,
            SeverityLevel.Medium,
            SeverityLevel.Low,
            SeverityLevel.Info
        };

        /// <summary>
        /// Constructor for dependency injection.
        /// </summary>
        /// <param name="reportService">The report generator service injected by DI container.</param>
        public ReportViewModel(IReportGeneratorService reportService)
        {
            _reportService = reportService ?? throw new ArgumentNullException(nameof(reportService));
        }
        
        public async Task UpdateData(NetworkStatistics statistics, List<SecurityThreat> threats)
        {
            // Ensure we're on the UI thread for the entire update process
            if (!Dispatcher.CheckAccess())
            {
                await Dispatcher.InvokeAsync(async () => await UpdateData(statistics, threats));
                return;
            }
            
            _currentStatistics = statistics;
            _currentThreats = threats;
            GenerationStatus = $"Data updated: {statistics.TotalPackets:N0} packets, {threats.Count} threats";
        }
        
        [RelayCommand]
        private async Task GenerateReport()
        {
            if (_currentStatistics == null)
            {
                GenerationStatus = "No data available for report generation";
                return;
            }
            
            try
            {
                IsGenerating = true;
                GenerationStatus = "Generating report...";
                
                var configuration = new ReportConfiguration
                {
                    IncludeExecutiveSummary = IncludeExecutiveSummary,
                    IncludeSecurityFindings = IncludeSecurityFindings,
                    IncludePerformanceAnalysis = IncludePerformanceAnalysis,
                    IncludeComplianceCheck = IncludeComplianceCheck,
                    IncludeRecommendations = IncludeRecommendations,
                    IncludeTechnicalDetails = IncludeTechnicalDetails,
                    IncludeRawData = IncludeRawData,
                    IncludePacketSamples = IncludePacketSamples,
                    IncludeNetworkDiagrams = IncludeNetworkDiagrams,
                    IncludeRemediationTimeline = IncludeRemediationTimeline,
                    IncludeCostEstimates = IncludeCostEstimates,
                    MaxFindingsPerCategory = MaxFindingsPerCategory,
                    MinimumSeverity = MinimumSeverity
                };
                
                CurrentReport = await _reportService.GenerateReportAsync(
                    _currentStatistics,
                    _currentThreats,
                    configuration,
                    SelectedReportType
                );
                
                UpdateReportDisplay();
                
                HasReport = true;
                GenerationStatus = $"Report generated successfully at {DateTime.Now:HH:mm:ss}";
                ReportGeneratedTime = CurrentReport.GeneratedAt.ToString("yyyy-MM-dd HH:mm:ss UTC");
            }
            catch (Exception ex)
            {
                GenerationStatus = $"Error generating report: {ex.Message}";
            }
            finally
            {
                IsGenerating = false;
            }
        }
        
        private void UpdateReportDisplay()
        {
            if (CurrentReport == null) return;
            
            // Update executive summary
            if (CurrentReport.ExecutiveSummary != null)
            {
                ExecutiveSummaryText = CurrentReport.ExecutiveSummary.Overview;
                SecurityScore = CurrentReport.ExecutiveSummary.SecurityScore;
                ComplianceScore = CurrentReport.ExecutiveSummary.ComplianceScore;
                OverallRiskLevel = CurrentReport.ExecutiveSummary.OverallRiskLevel;
            }
            
            // Update findings statistics
            TotalFindings = CurrentReport.SecurityFindings.Count;
            CriticalFindings = CurrentReport.SecurityFindings.Count(f => f.Severity == SeverityLevel.Critical);
            HighFindings = CurrentReport.SecurityFindings.Count(f => f.Severity == SeverityLevel.High);
            MediumFindings = CurrentReport.SecurityFindings.Count(f => f.Severity == SeverityLevel.Medium);
            LowFindings = CurrentReport.SecurityFindings.Count(f => f.Severity == SeverityLevel.Low);
            
            // Update security findings display
            SecurityFindings.Clear();
            foreach (var finding in CurrentReport.SecurityFindings.Take(10))
            {
                SecurityFindings.Add(new SecurityFindingViewModel
                {
                    Title = finding.Title,
                    Severity = finding.Severity.ToString(),
                    SeverityColor = GetSeverityColor(finding.Severity),
                    Description = finding.Description,
                    AffectedSystemsCount = finding.AffectedSystems.Count,
                    RemediationSummary = finding.Remediation.Summary,
                    RemediationPriority = finding.Remediation.Priority.ToString(),
                    RiskScore = finding.RiskScore
                });
            }
            
            // Update recommendations
            Recommendations.Clear();
            foreach (var rec in CurrentReport.Recommendations.Take(10))
            {
                Recommendations.Add(new RecommendationViewModel
                {
                    Title = rec.Title,
                    Priority = rec.Priority.ToString(),
                    PriorityColor = GetPriorityColor(rec.Priority),
                    Description = rec.Description,
                    Benefit = rec.Benefit,
                    EstimatedTimeframe = rec.EstimatedTimeframe,
                    ExpectedImprovement = rec.ExpectedImprovement
                });
            }
            
            // Update risk assessment
            if (CurrentReport.RiskAssessment != null)
            {
                RiskAssessmentText = $"Overall Risk Score: {CurrentReport.RiskAssessment.OverallRiskScore:F1}/100\n" +
                                   $"Risk Level: {CurrentReport.RiskAssessment.RiskLevel}\n" +
                                   $"Trend: {CurrentReport.RiskAssessment.RiskTrend}";
            }
            
            // Update remediation plan
            RemediationPhases.Clear();
            if (CurrentReport.RemediationPlan?.Phases != null)
            {
                foreach (var phase in CurrentReport.RemediationPlan.Phases)
                {
                    RemediationPhases.Add(new RemediationPhaseViewModel
                    {
                        PhaseNumber = phase.PhaseNumber,
                        Name = phase.Name,
                        Description = phase.Description,
                        StartDate = phase.StartDate.ToString("yyyy-MM-dd"),
                        EndDate = phase.EndDate.ToString("yyyy-MM-dd"),
                        TaskCount = phase.Tasks.Count,
                        SuccessCriteria = phase.SuccessCriteria
                    });
                }
            }
        }
        
        [RelayCommand]
        private async Task ExportHtml()
        {
            if (CurrentReport == null)
            {
                GenerationStatus = "No report to export";
                return;
            }
            
            try
            {
                GenerationStatus = "Exporting to HTML...";
                var html = await _reportService.ExportToHtmlAsync(CurrentReport);
                
                // Save to file
                var fileName = $"NetworkAnalysisReport_{DateTime.Now:yyyyMMdd_HHmmss}.html";
                var filePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), fileName);
                
                await File.WriteAllTextAsync(filePath, html);
                GenerationStatus = $"Report exported to {filePath}";
            }
            catch (Exception ex)
            {
                GenerationStatus = $"Export failed: {ex.Message}";
            }
        }
        
        [RelayCommand]
        private Task ExportPdf()
        {
            if (CurrentReport == null)
            {
                GenerationStatus = "No report to export";
                return Task.CompletedTask;
            }
            
            GenerationStatus = "PDF export functionality coming soon";
            // PDF export would be implemented here
            return Task.CompletedTask;
        }
        
        [RelayCommand]
        private async Task ExportJson()
        {
            if (CurrentReport == null)
            {
                GenerationStatus = "No report to export";
                return;
            }
            
            try
            {
                GenerationStatus = "Exporting to JSON...";
                var json = await _reportService.ExportToJsonAsync(CurrentReport);
                
                // Save to file
                var fileName = $"NetworkAnalysisReport_{DateTime.Now:yyyyMMdd_HHmmss}.json";
                var filePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), fileName);
                
                await File.WriteAllTextAsync(filePath, json);
                GenerationStatus = $"Report exported to {filePath}";
            }
            catch (Exception ex)
            {
                GenerationStatus = $"Export failed: {ex.Message}";
            }
        }
        
        [RelayCommand]
        private void ResetConfiguration()
        {
            SelectedReportType = ReportType.Technical;
            IncludeExecutiveSummary = true;
            IncludeSecurityFindings = true;
            IncludePerformanceAnalysis = true;
            IncludeComplianceCheck = true;
            IncludeRecommendations = true;
            IncludeTechnicalDetails = false;
            IncludeRawData = false;
            IncludePacketSamples = false;
            IncludeNetworkDiagrams = true;
            IncludeRemediationTimeline = true;
            IncludeCostEstimates = false;
            MaxFindingsPerCategory = 10;
            MinimumSeverity = SeverityLevel.Low;
            
            GenerationStatus = "Configuration reset to defaults";
        }
        
        private string GetSeverityColor(SeverityLevel severity)
        {
            return severity switch
            {
                SeverityLevel.Critical => ThemeColorHelper.GetColorHex("ColorDanger", "#EF4444"),
                SeverityLevel.High => ThemeColorHelper.GetColorHex("ColorWarning", "#F59E0B"),
                SeverityLevel.Medium => ThemeColorHelper.GetColorHex("AccentBlue", "#3B82F6"),
                SeverityLevel.Low => ThemeColorHelper.GetColorHex("ColorSuccess", "#10B981"),
                _ => ThemeColorHelper.GetColorHex("TextMuted", "#6B7280")
            };
        }

        private string GetPriorityColor(RemediationPriority priority)
        {
            return priority switch
            {
                RemediationPriority.Immediate => ThemeColorHelper.GetColorHex("ColorDanger", "#EF4444"),
                RemediationPriority.High => ThemeColorHelper.GetColorHex("ColorWarning", "#F59E0B"),
                RemediationPriority.Medium => ThemeColorHelper.GetColorHex("AccentBlue", "#3B82F6"),
                RemediationPriority.Low => ThemeColorHelper.GetColorHex("ColorSuccess", "#10B981"),
                _ => ThemeColorHelper.GetColorHex("TextMuted", "#6B7280")
            };
        }
    }
    
    public class SecurityFindingViewModel
    {
        public string Title { get; set; } = "";
        public string Severity { get; set; } = "";
        public string SeverityColor { get; set; } = "";
        public string Description { get; set; } = "";
        public int AffectedSystemsCount { get; set; }
        public string RemediationSummary { get; set; } = "";
        public string RemediationPriority { get; set; } = "";
        public double RiskScore { get; set; }
    }
    
    public class RecommendationViewModel
    {
        public string Title { get; set; } = "";
        public string Priority { get; set; } = "";
        public string PriorityColor { get; set; } = "";
        public string Description { get; set; } = "";
        public string Benefit { get; set; } = "";
        public string EstimatedTimeframe { get; set; } = "";
        public double ExpectedImprovement { get; set; }
    }
    
    public class RemediationPhaseViewModel
    {
        public int PhaseNumber { get; set; }
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public string StartDate { get; set; } = "";
        public string EndDate { get; set; } = "";
        public int TaskCount { get; set; }
        public string SuccessCriteria { get; set; } = "";
    }
}