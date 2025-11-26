using System.Collections.Generic;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.Reporting
{
    /// <summary>
    /// Interface for remediation plan generation.
    /// Creates prioritized action plans to address security findings.
    /// </summary>
    public interface IRemediationPlanner
    {
        /// <summary>
        /// Generates a comprehensive remediation plan from security findings.
        /// </summary>
        /// <param name="findings">Security findings requiring remediation.</param>
        /// <param name="recommendations">Additional recommendations for security improvements.</param>
        /// <returns>Structured remediation plan with phases, tasks, and timelines.</returns>
        Task<RemediationPlan> GenerateAsync(List<SecurityFinding> findings, List<Recommendation> recommendations);

        /// <summary>
        /// Generates remediation steps for a specific insecure service.
        /// </summary>
        /// <param name="port">The port number of the insecure service.</param>
        /// <param name="serviceName">The name of the insecure service.</param>
        /// <returns>Detailed remediation step with priority and technical instructions.</returns>
        RemediationStep GenerateServiceRemediationStep(int port, string serviceName);

        /// <summary>
        /// Generates recommendations based on security findings and performance issues.
        /// </summary>
        /// <param name="findings">Security findings to base recommendations on.</param>
        /// <param name="performanceIssues">Performance issues identified during analysis.</param>
        /// <returns>List of prioritized recommendations for improvement.</returns>
        Task<List<Recommendation>> GenerateRecommendationsAsync(List<SecurityFinding> findings, List<PerformanceIssue> performanceIssues);
    }
}
