using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Media;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.UI.Services;

namespace PCAPAnalyzer.UI.Controls;

/// <summary>
/// A custom control for displaying protocol badges with color coding.
/// Provides visual distinction for network protocols in the UI.
/// </summary>
public class ProtocolBadge : TemplatedControl
{
    private static IProtocolColorService? _colorService;

    // ==================== STYLED PROPERTIES ====================

    public static readonly StyledProperty<string> ProtocolProperty =
        AvaloniaProperty.Register<ProtocolBadge, string>(nameof(Protocol), defaultValue: "UNKNOWN");

    public static readonly StyledProperty<string> ProtocolDescriptionProperty =
        AvaloniaProperty.Register<ProtocolBadge, string>(nameof(ProtocolDescription));

    public static readonly StyledProperty<bool> ShowDotProperty =
        AvaloniaProperty.Register<ProtocolBadge, bool>(nameof(ShowDot), defaultValue: true);

    public static readonly StyledProperty<bool> ShowCategoryProperty =
        AvaloniaProperty.Register<ProtocolBadge, bool>(nameof(ShowCategory), defaultValue: false);

    // ==================== PROPERTIES ====================

    /// <summary>
    /// Gets or sets the protocol name (e.g., "TCP", "HTTP", "DNS").
    /// </summary>
    public string Protocol
    {
        get => GetValue(ProtocolProperty);
        set => SetValue(ProtocolProperty, value);
    }

    /// <summary>
    /// Gets or sets the protocol description (shown in tooltip).
    /// </summary>
    public string ProtocolDescription
    {
        get => GetValue(ProtocolDescriptionProperty);
        set => SetValue(ProtocolDescriptionProperty, value);
    }

    /// <summary>
    /// Gets or sets whether to show the colored dot indicator.
    /// </summary>
    public bool ShowDot
    {
        get => GetValue(ShowDotProperty);
        set => SetValue(ShowDotProperty, value);
    }

    /// <summary>
    /// Gets or sets whether to display category name instead of protocol.
    /// </summary>
    public bool ShowCategory
    {
        get => GetValue(ShowCategoryProperty);
        set => SetValue(ShowCategoryProperty, value);
    }

    // ==================== CONSTRUCTOR ====================

    public ProtocolBadge()
    {
        // Use DI container, fallback to direct instantiation only if DI not available
        _colorService ??= App.Services?.GetService<IProtocolColorService>() ?? new ProtocolColorService();
    }

    // ==================== PROPERTY CHANGE HANDLERS ====================

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);

        if (change.Property == ProtocolProperty || change.Property == ShowCategoryProperty)
        {
            UpdateColors();
        }
    }

    // ==================== COLOR UPDATE ====================

    private void UpdateColors()
    {
        if (_colorService == null || string.IsNullOrWhiteSpace(Protocol))
            return;

        try
        {
            var colorInfo = _colorService.GetProtocolColor(Protocol);

            // Parse primary color
            var primaryColor = Color.Parse(colorInfo.PrimaryColor);

            // Set foreground (text and dot color)
            SetValue(ForegroundProperty, new SolidColorBrush(primaryColor));

            // Set background (slightly transparent for better readability)
            var backgroundColor = Color.FromArgb(40, primaryColor.R, primaryColor.G, primaryColor.B);
            SetValue(BackgroundProperty, new SolidColorBrush(backgroundColor));

            // Set border (same as foreground)
            SetValue(BorderBrushProperty, new SolidColorBrush(primaryColor));
            SetValue(BorderThicknessProperty, new Thickness(1));

            // Set tooltip description
            if (ShowCategory)
            {
                var category = _colorService.GetProtocolCategory(Protocol);
                ProtocolDescription = $"{Protocol} ({category})";
            }
            else
            {
                ProtocolDescription = colorInfo.Description;
            }
        }
        catch
        {
            // Fallback colors if parsing fails
            SetValue(ForegroundProperty, Brushes.White);
            SetValue(BackgroundProperty, new SolidColorBrush(Color.FromArgb(40, 107, 114, 128)));
            SetValue(BorderBrushProperty, new SolidColorBrush(Color.FromRgb(107, 114, 128)));
            ProtocolDescription = Protocol;
        }
    }

    // ==================== PUBLIC METHODS ====================

    /// <summary>
    /// Set the protocol color service (for dependency injection).
    /// </summary>
    public static void SetColorService(IProtocolColorService colorService)
    {
        _colorService = colorService;
    }

    /// <summary>
    /// Get the current color for the protocol.
    /// </summary>
    public string GetCurrentColor()
    {
        if (_colorService == null || string.IsNullOrWhiteSpace(Protocol))
            return "#6B7280";

        return _colorService.GetProtocolColorHex(Protocol);
    }

    /// <summary>
    /// Get the protocol category.
    /// </summary>
    public string GetCategory()
    {
        if (_colorService == null || string.IsNullOrWhiteSpace(Protocol))
            return "Unknown";

        return _colorService.GetProtocolCategory(Protocol);
    }
}
