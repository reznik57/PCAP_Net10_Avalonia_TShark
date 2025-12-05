using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.Converters;

public class BoolToColorConverter : IValueConverter
{
    public static readonly BoolToColorConverter Instance = new();

    /// <summary>
    /// Converter for countdown background: red when active, default dark when not
    /// </summary>
    public static readonly IValueConverter CountdownBackground = new FuncValueConverter<bool, IBrush>(
        isActive => ThemeColorHelper.GetCountdownBackgroundBrush(isActive));

    /// <summary>
    /// Converter for countdown border: bright red when active, blue when not
    /// </summary>
    public static readonly IValueConverter CountdownBorder = new FuncValueConverter<bool, IBrush>(
        isActive => ThemeColorHelper.GetCountdownBorderBrush(isActive));

    // ==================== QUICK FILTER MODE CONVERTERS ====================

    /// <summary>
    /// Border color for Quick Filter section: Green for INCLUDE, Red for EXCLUDE
    /// </summary>
    public static readonly IValueConverter QuickFilterBorder = new FuncValueConverter<bool, IBrush>(
        isIncludeMode => ThemeColorHelper.GetQuickFilterBorderBrush(isIncludeMode));

    /// <summary>
    /// Background color for Quick Filter section: Dark blue-green for INCLUDE, Dark red for EXCLUDE
    /// </summary>
    public static readonly IValueConverter QuickFilterBackground = new FuncValueConverter<bool, IBrush>(
        isIncludeMode => ThemeColorHelper.GetQuickFilterBackgroundBrush(isIncludeMode));

    /// <summary>
    /// Title color for Quick Filter header: Green for INCLUDE, Red for EXCLUDE
    /// </summary>
    public static readonly IValueConverter QuickFilterTitle = new FuncValueConverter<bool, IBrush>(
        isIncludeMode => ThemeColorHelper.GetQuickFilterBorderBrush(isIncludeMode));

    /// <summary>
    /// Mode label text color: Light green for INCLUDE, Light red for EXCLUDE
    /// </summary>
    public static readonly IValueConverter QuickFilterModeLabelForeground = new FuncValueConverter<bool, IBrush>(
        isIncludeMode => ThemeColorHelper.GetQuickFilterLabelTextBrush(isIncludeMode));

    /// <summary>
    /// Mode label background: Dark green for INCLUDE, Dark red for EXCLUDE
    /// </summary>
    public static readonly IValueConverter QuickFilterModeLabelBackground = new FuncValueConverter<bool, IBrush>(
        isIncludeMode => ThemeColorHelper.GetQuickFilterLabelBgBrush(isIncludeMode));

    /// <summary>
    /// Mode label border: Green for INCLUDE, Red for EXCLUDE
    /// </summary>
    public static readonly IValueConverter QuickFilterModeLabelBorder = new FuncValueConverter<bool, IBrush>(
        isIncludeMode => ThemeColorHelper.GetQuickFilterLabelBorderBrush(isIncludeMode));

    /// <summary>
    /// Mode label text: "INCLUDE MODE" or "EXCLUDE MODE"
    /// </summary>
    public static readonly IValueConverter QuickFilterModeText = new FuncValueConverter<bool, string>(
        isIncludeMode => isIncludeMode ? "INCLUDE MODE" : "EXCLUDE MODE");

    /// <summary>
    /// Mode icon: ✅ for INCLUDE, 🚫 for EXCLUDE
    /// </summary>
    public static readonly IValueConverter QuickFilterModeIcon = new FuncValueConverter<bool, string>(
        isIncludeMode => isIncludeMode ? "✅" : "🚫");

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is bool isActive)
        {
            // Red if active (threat detected), Green if not
            return isActive
                ? ThemeColorHelper.GetColorHex("ThreatCritical", "#EF4444")
                : ThemeColorHelper.GetColorHex("ColorSuccess", "#10B981");
        }
        return ThemeColorHelper.ChartGrayHex;
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
