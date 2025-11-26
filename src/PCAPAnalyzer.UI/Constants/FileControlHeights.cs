namespace PCAPAnalyzer.UI.Constants;

/// <summary>
/// Defines standard heights for FileSelectionControl states.
/// Centralizes magic numbers for consistent UI sizing.
/// </summary>
public static class FileControlHeights
{
    /// <summary>
    /// Empty state - prominent drop zone for file selection (130px)
    /// </summary>
    public const double Empty = 130;

    /// <summary>
    /// File selected - countdown display with file info (90px)
    /// </summary>
    public const double FileSelected = 90;

    /// <summary>
    /// Analyzing - progress bar with full metrics display (130px)
    /// </summary>
    public const double Analyzing = 130;

    /// <summary>
    /// Complete - 4 metric cards + stage breakdown + action buttons (160px)
    /// </summary>
    public const double Complete = 160;

    /// <summary>
    /// Collapsed - minimal indicator bar (28px)
    /// </summary>
    public const double Collapsed = 28;
}
