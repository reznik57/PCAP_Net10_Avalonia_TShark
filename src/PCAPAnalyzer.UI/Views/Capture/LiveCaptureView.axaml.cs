using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace PCAPAnalyzer.UI.Views.Capture;

/// <summary>
/// Code-behind for LiveCaptureView
/// Minimal code-behind following MVVM pattern - all logic in ViewModel
/// </summary>
public partial class LiveCaptureView : UserControl
{
    public LiveCaptureView()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
