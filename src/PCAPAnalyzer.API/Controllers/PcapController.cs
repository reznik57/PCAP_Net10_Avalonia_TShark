using Microsoft.AspNetCore.Mvc;
using PCAPAnalyzer.API.DTOs;
using PCAPAnalyzer.API.Models;
using PCAPAnalyzer.API.Services;

namespace PCAPAnalyzer.API.Controllers;

/// <summary>
/// PCAP file management and analysis endpoints
/// </summary>
[ApiController]
[Route("api/v1/[controller]")]
[Produces("application/json")]
public class PcapController : ControllerBase
{
    private readonly IPcapAnalysisService _analysisService;
    private readonly ILogger<PcapController> _logger;

    public PcapController(IPcapAnalysisService analysisService, ILogger<PcapController> logger)
    {
        _analysisService = analysisService;
        _logger = logger;
    }

    /// <summary>
    /// Upload a PCAP file for analysis
    /// </summary>
    /// <param name="request">PCAP upload request</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Upload response with PCAP ID</returns>
    [HttpPost("upload")]
    [ProducesResponseType(typeof(ApiResponse<PcapUploadResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(Microsoft.AspNetCore.Mvc.ProblemDetails), StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<ApiResponse<PcapUploadResponse>>> UploadPcap(
        [FromBody] PcapUploadRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            var response = await _analysisService.UploadPcapAsync(request, cancellationToken);
            return Ok(ApiResponse<PcapUploadResponse>.SuccessResult(response, "PCAP file uploaded successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error uploading PCAP file");
            return BadRequest(ApiResponse<PcapUploadResponse>.ErrorResult("Failed to upload PCAP file", new List<string> { ex.Message }));
        }
    }

    /// <summary>
    /// Start analysis on an uploaded PCAP file
    /// </summary>
    /// <param name="id">PCAP ID</param>
    /// <param name="request">Analysis configuration</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Analysis status</returns>
    [HttpPost("{id}/analyze")]
    [ProducesResponseType(typeof(ApiResponse<AnalysisStatusResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(Microsoft.AspNetCore.Mvc.ProblemDetails), StatusCodes.Status404NotFound)]
    public async Task<ActionResult<ApiResponse<AnalysisStatusResponse>>> AnalyzePcap(
        string id,
        [FromBody] AnalyzeRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            var response = await _analysisService.StartAnalysisAsync(id, request, cancellationToken);
            return Ok(ApiResponse<AnalysisStatusResponse>.SuccessResult(response, "Analysis started"));
        }
        catch (FileNotFoundException ex)
        {
            return NotFound(ApiResponse<AnalysisStatusResponse>.ErrorResult(ex.Message));
        }
    }

    /// <summary>
    /// Get analysis status for a PCAP file
    /// </summary>
    /// <param name="id">PCAP ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Analysis status</returns>
    [HttpGet("{id}/status")]
    [ProducesResponseType(typeof(ApiResponse<AnalysisStatusResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(Microsoft.AspNetCore.Mvc.ProblemDetails), StatusCodes.Status404NotFound)]
    public async Task<ActionResult<ApiResponse<AnalysisStatusResponse>>> GetStatus(
        string id,
        CancellationToken cancellationToken)
    {
        try
        {
            var response = await _analysisService.GetAnalysisStatusAsync(id, cancellationToken);
            return Ok(ApiResponse<AnalysisStatusResponse>.SuccessResult(response));
        }
        catch (FileNotFoundException ex)
        {
            return NotFound(ApiResponse<AnalysisStatusResponse>.ErrorResult(ex.Message));
        }
    }

    /// <summary>
    /// Get analysis results for a completed PCAP analysis
    /// </summary>
    /// <param name="id">PCAP ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Analysis results</returns>
    [HttpGet("{id}/results")]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(Microsoft.AspNetCore.Mvc.ProblemDetails), StatusCodes.Status404NotFound)]
    public async Task<ActionResult<ApiResponse<object>>> GetResults(
        string id,
        CancellationToken cancellationToken)
    {
        try
        {
            var results = await _analysisService.GetAnalysisResultsAsync(id, cancellationToken);
            return Ok(ApiResponse<object>.SuccessResult(results));
        }
        catch (FileNotFoundException ex)
        {
            return NotFound(ApiResponse<object>.ErrorResult(ex.Message));
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(ApiResponse<object>.ErrorResult(ex.Message));
        }
    }

    /// <summary>
    /// Delete a PCAP file and its analysis results
    /// </summary>
    /// <param name="id">PCAP ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Success status</returns>
    [HttpDelete("{id}")]
    [ProducesResponseType(typeof(ApiResponse<bool>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(Microsoft.AspNetCore.Mvc.ProblemDetails), StatusCodes.Status404NotFound)]
    public async Task<ActionResult<ApiResponse<bool>>> DeletePcap(
        string id,
        CancellationToken cancellationToken)
    {
        var success = await _analysisService.DeletePcapAsync(id, cancellationToken);
        if (success)
            return Ok(ApiResponse<bool>.SuccessResult(true, "PCAP file deleted successfully"));

        return NotFound(ApiResponse<bool>.ErrorResult("PCAP file not found"));
    }
}
