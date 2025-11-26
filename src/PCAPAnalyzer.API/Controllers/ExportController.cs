using Microsoft.AspNetCore.Mvc;
using PCAPAnalyzer.API.DTOs;
using PCAPAnalyzer.API.Models;
using PCAPAnalyzer.API.Services;

namespace PCAPAnalyzer.API.Controllers;

/// <summary>
/// Export and report generation endpoints
/// </summary>
[ApiController]
[Route("api/v1/export")]
[Produces("application/json")]
public class ExportController : ControllerBase
{
    private readonly IExportService _exportService;
    private readonly ILogger<ExportController> _logger;

    public ExportController(IExportService exportService, ILogger<ExportController> logger)
    {
        _exportService = exportService;
        _logger = logger;
    }

    /// <summary>
    /// Export analysis results to PDF
    /// </summary>
    [HttpGet("{id}/pdf")]
    [ProducesResponseType(typeof(ApiResponse<ExportResponse>), StatusCodes.Status200OK)]
    public async Task<ActionResult<ApiResponse<ExportResponse>>> ExportToPdf(
        string id,
        [FromQuery] ExportRequest? request,
        CancellationToken cancellationToken)
    {
        request ??= new ExportRequest { Format = "pdf" };
        var response = await _exportService.ExportToPdfAsync(id, request, cancellationToken);
        return Ok(ApiResponse<ExportResponse>.SuccessResult(response, "PDF export created"));
    }

    /// <summary>
    /// Export analysis results to CSV
    /// </summary>
    [HttpGet("{id}/csv")]
    [ProducesResponseType(typeof(ApiResponse<ExportResponse>), StatusCodes.Status200OK)]
    public async Task<ActionResult<ApiResponse<ExportResponse>>> ExportToCsv(
        string id,
        [FromQuery] ExportRequest? request,
        CancellationToken cancellationToken)
    {
        request ??= new ExportRequest { Format = "csv" };
        var response = await _exportService.ExportToCsvAsync(id, request, cancellationToken);
        return Ok(ApiResponse<ExportResponse>.SuccessResult(response, "CSV export created"));
    }

    /// <summary>
    /// Export analysis results to JSON
    /// </summary>
    [HttpGet("{id}/json")]
    [ProducesResponseType(typeof(ApiResponse<ExportResponse>), StatusCodes.Status200OK)]
    public async Task<ActionResult<ApiResponse<ExportResponse>>> ExportToJson(
        string id,
        [FromQuery] ExportRequest? request,
        CancellationToken cancellationToken)
    {
        request ??= new ExportRequest { Format = "json" };
        var response = await _exportService.ExportToJsonAsync(id, request, cancellationToken);
        return Ok(ApiResponse<ExportResponse>.SuccessResult(response, "JSON export created"));
    }
}
