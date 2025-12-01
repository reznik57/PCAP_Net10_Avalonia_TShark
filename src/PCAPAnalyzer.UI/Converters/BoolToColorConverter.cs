using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;

namespace PCAPAnalyzer.UI.Converters;

public class BoolToColorConverter : IValueConverter
{
    public static readonly BoolToColorConverter Instance = new();

    /// <summary>
    /// Converter for countdown background: red when active, default dark when not
    /// </summary>
    public static readonly IValueConverter CountdownBackground = new FuncValueConverter<bool, IBrush>(
        isActive => isActive
            ? new SolidColorBrush(Color.FromArgb(0xE0, 0xB9, 0x1C, 0x1C)) // Dark red background (#B91C1C with transparency)
            : new SolidColorBrush(Color.Parse("#0D1117")));

    /// <summary>
    /// Converter for countdown border: bright red when active, blue when not
    /// </summary>
    public static readonly IValueConverter CountdownBorder = new FuncValueConverter<bool, IBrush>(
        isActive => isActive
            ? new SolidColorBrush(Color.Parse("#DC2626")) // Bright red border
            : new SolidColorBrush(Color.Parse("#58A6FF"))); // Blue border

    // ==================== QUICK FILTER MODE CONVERTERS ====================

    /// <summary>
    /// Border color for Quick Filter section: Green (#10B981) for INCLUDE, Red (#EF4444) for EXCLUDE
    /// </summary>
    public static readonly IValueConverter QuickFilterBorder = new FuncValueConverter<bool, IBrush>(
        isIncludeMode => isIncludeMode
            ? new SolidColorBrush(Color.Parse("#10B981")) // Green for Include
            : new SolidColorBrush(Color.Parse("#EF4444"))); // Red for Exclude

    /// <summary>
    /// Background color for Quick Filter section: Dark blue-green for INCLUDE, Dark red for EXCLUDE
    /// </summary>
    public static readonly IValueConverter QuickFilterBackground = new FuncValueConverter<bool, IBrush>(
        isIncludeMode => isIncludeMode
            ? new SolidColorBrush(Color.Parse("#0D1620")) // Dark blue-green for Include
            : new SolidColorBrush(Color.Parse("#1A0D0D"))); // Dark red for Exclude

    /// <summary>
    /// Title color for Quick Filter header: Green (#10B981) for INCLUDE, Red (#EF4444) for EXCLUDE
    /// </summary>
    public static readonly IValueConverter QuickFilterTitle = new FuncValueConverter<bool, IBrush>(
        isIncludeMode => isIncludeMode
            ? new SolidColorBrush(Color.Parse("#10B981")) // Green for Include
            : new SolidColorBrush(Color.Parse("#EF4444"))); // Red for Exclude

    /// <summary>
    /// Mode label text color: Light green (#7EE787) for INCLUDE, Light red (#FF7B72) for EXCLUDE
    /// </summary>
    public static readonly IValueConverter QuickFilterModeLabelForeground = new FuncValueConverter<bool, IBrush>(
        isIncludeMode => isIncludeMode
            ? new SolidColorBrush(Color.Parse("#7EE787")) // Light green for Include
            : new SolidColorBrush(Color.Parse("#FF7B72"))); // Light red for Exclude

    /// <summary>
    /// Mode label background: Dark green (#1A3D1A) for INCLUDE, Dark red (#3D1A1A) for EXCLUDE
    /// </summary>
    public static readonly IValueConverter QuickFilterModeLabelBackground = new FuncValueConverter<bool, IBrush>(
        isIncludeMode => isIncludeMode
            ? new SolidColorBrush(Color.Parse("#1A3D1A")) // Dark green for Include
            : new SolidColorBrush(Color.Parse("#3D1A1A"))); // Dark red for Exclude

    /// <summary>
    /// Mode label border: Green (#2EA043) for INCLUDE, Red (#F85149) for EXCLUDE
    /// </summary>
    public static readonly IValueConverter QuickFilterModeLabelBorder = new FuncValueConverter<bool, IBrush>(
        isIncludeMode => isIncludeMode
            ? new SolidColorBrush(Color.Parse("#2EA043")) // Green border for Include
            : new SolidColorBrush(Color.Parse("#F85149"))); // Red border for Exclude

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
            return isActive ? "#EF4444" : "#10B981"; // Red if active (threat detected), Green if not
        }
        return "#6B7280"; // Gray default
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}