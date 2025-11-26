using Microsoft.AspNetCore.Mvc;
using PCAPAnalyzer.API.DTOs;
using PCAPAnalyzer.API.Models;
using PCAPAnalyzer.API.Services;

namespace PCAPAnalyzer.API.Controllers;

/// <summary>
/// Anomaly detection and ML model endpoints
/// </summary>
[ApiController]
[Route("api/v1/anomalies")]
[Produces("application/json")]
public class AnomaliesController : ControllerBase
{
    private readonly IAnomalyDetectionService _anomalyService;
    private readonly ILogger<AnomaliesController> _logger;

    public AnomaliesController(IAnomalyDetectionService anomalyService, ILogger<AnomaliesController> logger)
    {
        _anomalyService = anomalyService;
        _logger = logger;
    }

    /// <summary>
    /// Get detected anomalies for a PCAP file
    /// </summary>
    [HttpGet("{id}")]
    [ProducesResponseType(typeof(ApiResponse<IEnumerable<AnomalyDto>>), StatusCodes.Status200OK)]
    public async Task<ActionResult<ApiResponse<IEnumerable<AnomalyDto>>>> GetAnomalies(
        string id,
        CancellationToken cancellationToken)
    {
        var anomalies = await _anomalyService.GetAnomaliesAsync(id, cancellationToken);
        return Ok(ApiResponse<IEnumerable<AnomalyDto>>.SuccessResult(anomalies));
    }

    /// <summary>
    /// Train a new ML model for anomaly detection
    /// </summary>
    [HttpPost("train")]
    [ProducesResponseType(typeof(ApiResponse<ModelInfoDto>), StatusCodes.Status200OK)]
    public async Task<ActionResult<ApiResponse<ModelInfoDto>>> TrainModel(
        [FromBody] TrainModelRequest request,
        CancellationToken cancellationToken)
    {
        var modelInfo = await _anomalyService.TrainModelAsync(request, cancellationToken);
        return Ok(ApiResponse<ModelInfoDto>.SuccessResult(modelInfo, "Model training started"));
    }

    /// <summary>
    /// Get list of available ML models
    /// </summary>
    [HttpGet("models")]
    [ProducesResponseType(typeof(ApiResponse<IEnumerable<ModelInfoDto>>), StatusCodes.Status200OK)]
    public async Task<ActionResult<ApiResponse<IEnumerable<ModelInfoDto>>>> GetModels(
        CancellationToken cancellationToken)
    {
        var models = await _anomalyService.GetAvailableModelsAsync(cancellationToken);
        return Ok(ApiResponse<IEnumerable<ModelInfoDto>>.SuccessResult(models));
    }
}
