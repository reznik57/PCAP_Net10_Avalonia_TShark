using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.Views.Controls;

public partial class UnifiedFilterPanelControl : UserControl
{
    /// <summary>
    /// Defines the DefaultTabIndex property for auto-selecting the appropriate filter tab
    /// based on which page the control is placed on.
    /// 0 = General (Dashboard, default)
    /// 1 = Threats (Security Threats page)
    /// 2 = Anomalies (Anomalies page)
    /// 3 = VoiceQoS (Voice/QoS page)
    /// 4 = Country (Country Traffic page)
    /// </summary>
    public static readonly StyledProperty<int> DefaultTabIndexProperty =
        AvaloniaProperty.Register<UnifiedFilterPanelControl, int>(nameof(DefaultTabIndex), defaultValue: 0);

    public int DefaultTabIndex
    {
        get => GetValue(DefaultTabIndexProperty);
        set => SetValue(DefaultTabIndexProperty, value);
    }

    public UnifiedFilterPanelControl()
    {
        InitializeComponent();

        if (!Design.IsDesignMode)
        {
            DataContext = App.Services.GetRequiredService<UnifiedFilterPanelViewModel>();
        }
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        ApplyDefaultTabIndex();
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);

        // When IsVisible changes to true (tab becomes visible), apply the default tab index
        if (change.Property == IsVisibleProperty && change.NewValue is bool isVisible && isVisible)
        {
            ApplyDefaultTabIndex();
        }
    }

    private void ApplyDefaultTabIndex()
    {
        // Auto-select the tab based on the DefaultTabIndex property
        if (DataContext is UnifiedFilterPanelViewModel vm)
        {
            vm.SelectedTabIndex = DefaultTabIndex;
            DebugLogger.Log($"[UnifiedFilterPanel] Tab auto-selected: {DefaultTabIndex}");
        }
    }
}
