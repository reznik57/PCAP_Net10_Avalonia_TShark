using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace PCAPAnalyzer.UI.Controls;

/// <summary>
/// Live statistics panel custom control
/// Displays real-time capture metrics and charts
/// </summary>
public partial class LiveStatisticsPanel : UserControl
{
    public LiveStatisticsPanel()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
