using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;

namespace PCAPAnalyzer.UI.Views.Capture;

/// <summary>
/// Configuration dialog for live packet capture
/// </summary>
public partial class CaptureConfigurationDialog : Window
{
    public bool DialogResult { get; private set; }

    public CaptureConfigurationDialog()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }

    private void StartButton_Click(object? sender, RoutedEventArgs e)
    {
        DialogResult = true;
        Close();
    }

    private void CancelButton_Click(object? sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
