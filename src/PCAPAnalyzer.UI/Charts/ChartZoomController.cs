using System;
using LiveChartsCore.SkiaSharpView;

namespace PCAPAnalyzer.UI.Charts;

/// <summary>
/// Controls zoom state and calculations for timeline charts.
/// Encapsulates zoom logic to reduce complexity in chart ViewModels.
/// </summary>
public sealed class ChartZoomController
{
    private double _originalMinLimit;
    private double _originalMaxLimit;
    private bool _initialized;

    public double ZoomLevel { get; private set; } = 100;
    public double MinZoom { get; init; } = 50;
    public double MaxZoom { get; init; } = 200;
    public double ZoomStep { get; init; } = 5;

    public bool IsInitialized => _initialized;

    /// <summary>
    /// Initializes zoom with original axis limits.
    /// </summary>
    public void Initialize(double minLimit, double maxLimit)
    {
        _originalMinLimit = minLimit;
        _originalMaxLimit = maxLimit;
        _initialized = true;
        ZoomLevel = 100;
    }

    /// <summary>
    /// Resets to uninitialized state.
    /// </summary>
    public void Reset()
    {
        _initialized = false;
        ZoomLevel = 100;
    }

    /// <summary>
    /// Zooms in by one step.
    /// Returns true if zoom was applied.
    /// </summary>
    public bool ZoomIn()
    {
        if (ZoomLevel >= MaxZoom)
            return false;

        ZoomLevel = Math.Min(ZoomLevel + ZoomStep, MaxZoom);
        return true;
    }

    /// <summary>
    /// Zooms out by one step.
    /// Returns true if zoom was applied.
    /// </summary>
    public bool ZoomOut()
    {
        if (ZoomLevel <= MinZoom)
            return false;

        ZoomLevel = Math.Max(ZoomLevel - ZoomStep, MinZoom);
        return true;
    }

    /// <summary>
    /// Resets zoom to 100%.
    /// </summary>
    public void ResetZoom()
    {
        ZoomLevel = 100;
    }

    /// <summary>
    /// Applies current zoom level to an axis.
    /// </summary>
    public void ApplyToAxis(Axis axis)
    {
        if (axis is null || !_initialized)
            return;

        var zoomFactor = 100.0 / ZoomLevel;
        var originalRange = _originalMaxLimit - _originalMinLimit;
        var newRange = originalRange * zoomFactor;

        // Get current center or use original center
        var currentCenter = axis.MinLimit.HasValue && axis.MaxLimit.HasValue
            ? (axis.MinLimit.Value + axis.MaxLimit.Value) / 2
            : (_originalMinLimit + _originalMaxLimit) / 2;

        // Calculate new limits
        var newMin = currentCenter - newRange / 2;
        var newMax = currentCenter + newRange / 2;

        // Constrain to original bounds
        if (newMin < _originalMinLimit)
        {
            newMin = _originalMinLimit;
            newMax = newMin + newRange;
        }
        if (newMax > _originalMaxLimit)
        {
            newMax = _originalMaxLimit;
            newMin = newMax - newRange;
        }

        axis.MinLimit = newMin;
        axis.MaxLimit = newMax;
    }

    /// <summary>
    /// Gets the visible range at current zoom level.
    /// </summary>
    public (double Min, double Max) GetVisibleRange()
    {
        if (!_initialized)
            return (0, 0);

        var zoomFactor = 100.0 / ZoomLevel;
        var originalRange = _originalMaxLimit - _originalMinLimit;
        var newRange = originalRange * zoomFactor;
        var center = (_originalMinLimit + _originalMaxLimit) / 2;

        return (center - newRange / 2, center + newRange / 2);
    }
}
